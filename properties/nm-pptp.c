/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-pptp.c : GNOME UI dialogs for configuring PPTP VPN connections
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Based on work by David Zeuthen, <davidz@redhat.com>
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
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <glib/gi18n-lib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "../src/nm-pptp-service.h"
#include "../common-gnome/keyring-helpers.h"
#include "nm-pptp.h"
#include "import-export.h"
#include "advanced-dialog.h"

#define PPTP_PLUGIN_NAME    _("Point-to-Point Tunneling Protocol (PPTP)")
#define PPTP_PLUGIN_DESC    _("Compatible with Microsoft and other PPTP VPN servers.")
#define PPTP_PLUGIN_SERVICE NM_DBUS_SERVICE_PPTP


typedef void (*ChangedCallback) (GtkWidget *widget, gpointer user_data);

/************** plugin class **************/

static void pptp_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (PptpPluginUi, pptp_plugin_ui, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_INTERFACE,
											   pptp_plugin_ui_interface_init))

/************** UI widget class **************/

static void pptp_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (PptpPluginUiWidget, pptp_plugin_ui_widget, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE,
											   pptp_plugin_ui_widget_interface_init))

#define PPTP_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), PPTP_TYPE_PLUGIN_UI_WIDGET, PptpPluginUiWidgetPrivate))

typedef struct {
	GladeXML *xml;
	GtkWidget *widget;
	GtkSizeGroup *group;
	GtkWindowGroup *window_group;
	gboolean window_added;
	GHashTable *advanced;
} PptpPluginUiWidgetPrivate;


GQuark
pptp_plugin_ui_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("pptp-plugin-ui-error-quark");

	return error_quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
pptp_plugin_ui_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (PPTP_PLUGIN_UI_ERROR_UNKNOWN, "UnknownError"),
			/* The connection was missing invalid. */
			ENUM_ENTRY (PPTP_PLUGIN_UI_ERROR_INVALID_CONNECTION, "InvalidConnection"),
			/* The specified property was invalid. */
			ENUM_ENTRY (PPTP_PLUGIN_UI_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (PPTP_PLUGIN_UI_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The file to import could not be read. */
			ENUM_ENTRY (PPTP_PLUGIN_UI_ERROR_FILE_NOT_READABLE, "FileNotReadable"),
			/* The file to import could was not an PPTP client file. */
			ENUM_ENTRY (PPTP_PLUGIN_UI_ERROR_FILE_NOT_PPTP, "FileNotPPTP"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("PptpPluginUiError", values);
	}
	return etype;
}

static gboolean
check_validity (PptpPluginUiWidget *self, GError **error)
{
	PptpPluginUiWidgetPrivate *priv = PPTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             PPTP_PLUGIN_UI_ERROR,
		             PPTP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_PPTP_KEY_GATEWAY);
		return FALSE;
	}

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (PPTP_PLUGIN_UI_WIDGET (user_data), "changed");
}

static void
advanced_dialog_close_cb (GtkWidget *dialog, gpointer user_data)
{
	gtk_widget_hide (dialog);
	/* gtk_widget_destroy() will remove the window from the window group */
	gtk_widget_destroy (dialog);
}

static void
advanced_dialog_response_cb (GtkWidget *dialog, gint response, gpointer user_data)
{
	PptpPluginUiWidget *self = PPTP_PLUGIN_UI_WIDGET (user_data);
	PptpPluginUiWidgetPrivate *priv = PPTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GError *error = NULL;

	if (response != GTK_RESPONSE_OK) {
		advanced_dialog_close_cb (dialog, self);
		return;
	}

	if (priv->advanced)
		g_hash_table_destroy (priv->advanced);
	priv->advanced = advanced_dialog_new_hash_from_dialog (dialog, &error);
	if (!priv->advanced) {
		g_message ("%s: error reading advanced settings: %s", __func__, error->message);
		g_error_free (error);
	}
	advanced_dialog_close_cb (dialog, self);

	stuff_changed_cb (NULL, self);
}

static void
advanced_button_clicked_cb (GtkWidget *button, gpointer user_data)
{
	PptpPluginUiWidget *self = PPTP_PLUGIN_UI_WIDGET (user_data);
	PptpPluginUiWidgetPrivate *priv = PPTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *dialog, *toplevel;

	toplevel = gtk_widget_get_toplevel (priv->widget);
	g_return_if_fail (GTK_WIDGET_TOPLEVEL (toplevel));

	dialog = advanced_dialog_new (priv->advanced);
	if (!dialog) {
		g_warning ("%s: failed to create the Advanced dialog!", __func__);
		return;
	}

	gtk_window_group_add_window (priv->window_group, GTK_WINDOW (dialog));
	if (!priv->window_added) {
		gtk_window_group_add_window (priv->window_group, GTK_WINDOW (toplevel));
		priv->window_added = TRUE;
	}

	gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (toplevel));
	g_signal_connect (G_OBJECT (dialog), "response", G_CALLBACK (advanced_dialog_response_cb), self);
	g_signal_connect (G_OBJECT (dialog), "close", G_CALLBACK (advanced_dialog_close_cb), self);

	gtk_widget_show_all (dialog);
}

static void
show_toggled_cb (GtkCheckButton *button, PptpPluginUiWidget *self)
{
	PptpPluginUiWidgetPrivate *priv = PPTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	gboolean visible;

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));

	widget = glade_xml_get_widget (priv->xml, "user_password_entry");
	g_assert (widget);
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
}

static GtkWidget *
fill_password (GladeXML *xml,
               const char *widget_name,
               NMConnection *connection,
               const char *password_type)
{
	GtkWidget *widget = NULL;
	gchar *password = NULL;

	widget = glade_xml_get_widget (xml, widget_name);
	g_assert (widget);

	if (!connection)
		return widget;

	password = NULL;

	if (nm_connection_get_scope (connection) == NM_CONNECTION_SCOPE_SYSTEM) {
		NMSettingVPN *s_vpn;

		s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
		if (s_vpn) {
			const gchar *tmp = NULL;

			tmp = nm_setting_vpn_get_secret (s_vpn, password_type);
			if (tmp)
				password = gnome_keyring_memory_strdup (tmp);
		}
	} else {
		NMSettingConnection *s_con = NULL;
		gboolean unused;
		const char *uuid;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
		uuid = nm_setting_connection_get_uuid (s_con);
		password = keyring_helpers_lookup_secret (uuid,
		                                          password_type,
		                                          &unused);
	}

	if (password) {
		gtk_entry_set_text (GTK_ENTRY (widget), password);
		gnome_keyring_memory_free (password);
	}

	return widget;
}

static void
fill_vpn_passwords (GladeXML *xml,
                    GtkSizeGroup *group,
                    NMConnection *connection,
                    ChangedCallback changed_cb,
                    gpointer user_data)
{
	GtkWidget *w = NULL;

	w = fill_password (xml, "user_password_entry", connection, NM_PPTP_KEY_PASSWORD);
	if (w) {
		gtk_size_group_add_widget (group, w);
		g_signal_connect (w, "changed", G_CALLBACK (changed_cb), user_data);
	} else {
		g_error ("No user_password_entry in glade file!");
	}
}

static gboolean
init_plugin_ui (PptpPluginUiWidget *self, NMConnection *connection, GError **error)
{
	PptpPluginUiWidgetPrivate *priv = PPTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	const char *value;

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_GATEWAY);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "user_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_USER);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "domain_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_DOMAIN);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "advanced_button");
	g_signal_connect (G_OBJECT (widget), "clicked", G_CALLBACK (advanced_button_clicked_cb), self);

	widget = glade_xml_get_widget (priv->xml, "show_passwords_checkbutton");
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "toggled",
	                  (GCallback) show_toggled_cb,
	                  self);

	fill_vpn_passwords (priv->xml, priv->group, connection, stuff_changed_cb, self);

	return TRUE;
}

static GObject *
get_widget (NMVpnPluginUiWidgetInterface *iface)
{
	PptpPluginUiWidget *self = PPTP_PLUGIN_UI_WIDGET (iface);
	PptpPluginUiWidgetPrivate *priv = PPTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static void
hash_copy_advanced (gpointer key, gpointer data, gpointer user_data)
{
	NMSettingVPN *s_vpn = NM_SETTING_VPN (user_data);

	nm_setting_vpn_add_data_item (s_vpn, (const char *) key, (const char *) data);
}

static gboolean
update_connection (NMVpnPluginUiWidgetInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	PptpPluginUiWidget *self = PPTP_PLUGIN_UI_WIDGET (iface);
	PptpPluginUiWidgetPrivate *priv = PPTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	const char *str;
	gboolean valid = FALSE;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_PPTP, NULL);

	/* Gateway */
	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_PPTP_KEY_GATEWAY, str);

	/* Username */
	widget = glade_xml_get_widget (priv->xml, "user_entry");
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_PPTP_KEY_USER, str);

	/* Domain */
	widget = glade_xml_get_widget (priv->xml, "domain_entry");
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_PPTP_KEY_DOMAIN, str);

	if (priv->advanced)
		g_hash_table_foreach (priv->advanced, hash_copy_advanced, s_vpn);

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	valid = TRUE;

	return valid;
}

static gboolean
save_secrets (NMVpnPluginUiWidgetInterface *iface,
              NMConnection *connection,
              GError **error)
{
	PptpPluginUiWidget *self = PPTP_PLUGIN_UI_WIDGET (iface);
	PptpPluginUiWidgetPrivate *priv = PPTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GnomeKeyringResult ret;
	NMSettingConnection *s_con;
	GtkWidget *widget;
	const char *str, *uuid, *id;

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	if (!s_con) {
		g_set_error (error,
		             PPTP_PLUGIN_UI_ERROR,
		             PPTP_PLUGIN_UI_ERROR_INVALID_CONNECTION,
		             "missing 'connection' setting");
		return FALSE;
	}

	id = nm_setting_connection_get_id (s_con);
	uuid = nm_setting_connection_get_uuid (s_con);

    widget = glade_xml_get_widget (priv->xml, "user_password_entry");
    g_assert (widget);
    str = gtk_entry_get_text (GTK_ENTRY (widget));
    if (str && strlen (str)) {
        ret = keyring_helpers_save_secret (uuid, id, NULL, NM_PPTP_KEY_PASSWORD, str);
        if (ret != GNOME_KEYRING_RESULT_OK)
            g_warning ("%s: failed to save user password to keyring.", __func__);
    } else
        keyring_helpers_delete_secret (uuid, NM_PPTP_KEY_PASSWORD);

	return TRUE;
}

static NMVpnPluginUiWidgetInterface *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnPluginUiWidgetInterface *object;
	PptpPluginUiWidgetPrivate *priv;
	char *glade_file;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = NM_VPN_PLUGIN_UI_WIDGET_INTERFACE (g_object_new (PPTP_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
		g_set_error (error, PPTP_PLUGIN_UI_ERROR, 0, "could not create pptp object");
		return NULL;
	}

	priv = PPTP_PLUGIN_UI_WIDGET_GET_PRIVATE (object);

	glade_file = g_strdup_printf ("%s/%s", GLADEDIR, "nm-pptp-dialog.glade");
	priv->xml = glade_xml_new (glade_file, "pptp-vbox", GETTEXT_PACKAGE);
	if (priv->xml == NULL) {
		g_set_error (error, PPTP_PLUGIN_UI_ERROR, 0,
		             "could not load required resources at %s", glade_file);
		g_free (glade_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (glade_file);

	priv->widget = glade_xml_get_widget (priv->xml, "pptp-vbox");
	if (!priv->widget) {
		g_set_error (error, PPTP_PLUGIN_UI_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	priv->window_group = gtk_window_group_new ();

	if (!init_plugin_ui (PPTP_PLUGIN_UI_WIDGET (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	priv->advanced = advanced_dialog_new_hash_from_connection (connection, error);
	if (!priv->advanced) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	PptpPluginUiWidget *plugin = PPTP_PLUGIN_UI_WIDGET (object);
	PptpPluginUiWidgetPrivate *priv = PPTP_PLUGIN_UI_WIDGET_GET_PRIVATE (plugin);

	if (priv->group)
		g_object_unref (priv->group);

	if (priv->window_group)
		g_object_unref (priv->window_group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->xml)
		g_object_unref (priv->xml);

	if (priv->advanced)
		g_hash_table_destroy (priv->advanced);

	G_OBJECT_CLASS (pptp_plugin_ui_widget_parent_class)->dispose (object);
}

static void
pptp_plugin_ui_widget_class_init (PptpPluginUiWidgetClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (PptpPluginUiWidgetPrivate));

	object_class->dispose = dispose;
}

static void
pptp_plugin_ui_widget_init (PptpPluginUiWidget *plugin)
{
}

static void
pptp_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
	iface_class->save_secrets = save_secrets;
}

static gboolean
delete_connection (NMVpnPluginUiInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	NMSettingConnection *s_con = NULL;
	const char *uuid;

	/* Remove any secrets in the keyring associated with this connection's UUID */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection,
			NM_TYPE_SETTING_CONNECTION);
	if (!s_con) {
		g_set_error (error,
		             PPTP_PLUGIN_UI_ERROR,
		             PPTP_PLUGIN_UI_ERROR_INVALID_CONNECTION,
		             "missing 'connection' setting");
		return FALSE;
	}

	uuid = nm_setting_connection_get_uuid (s_con);
	keyring_helpers_delete_secret (uuid, NM_PPTP_KEY_PASSWORD);

	return TRUE;
}

static NMConnection *
import (NMVpnPluginUiInterface *iface, const char *path, GError **error)
{
	NMConnection *connection = NULL;
	char *contents = NULL;
	char **lines = NULL;
	char *ext;

	ext = strrchr (path, '.');
	if (!ext) {
		g_set_error (error,
		             PPTP_PLUGIN_UI_ERROR,
		             PPTP_PLUGIN_UI_ERROR_FILE_NOT_PPTP,
		             "unknown PPTP file extension");
		goto out;
	}

	if (strcmp (ext, ".conf") && strcmp (ext, ".cnf")) {
		g_set_error (error,
		             PPTP_PLUGIN_UI_ERROR,
		             PPTP_PLUGIN_UI_ERROR_FILE_NOT_PPTP,
		             "unknown PPTP file extension");
		goto out;
	}

	if (!g_file_get_contents (path, &contents, NULL, error))
		return NULL;

	lines = g_strsplit_set (contents, "\r\n", 0);
	if (g_strv_length (lines) <= 1) {
		g_set_error (error,
		             PPTP_PLUGIN_UI_ERROR,
		             PPTP_PLUGIN_UI_ERROR_FILE_NOT_READABLE,
		             "not a valid PPTP configuration file");
		goto out;
	}

	connection = do_import (path, lines, error);

out:
	if (lines)
		g_strfreev (lines);
	g_free (contents);
	return connection;
}

static gboolean
export (NMVpnPluginUiInterface *iface,
        const char *path,
        NMConnection *connection,
        GError **error)
{
	return do_export (path, connection, error);
}

static char *
get_suggested_name (NMVpnPluginUiInterface *iface, NMConnection *connection)
{
	NMSettingConnection *s_con;
	const char *id;

	g_return_val_if_fail (connection != NULL, NULL);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_return_val_if_fail (s_con != NULL, NULL);

	id = nm_setting_connection_get_id (s_con);
	g_return_val_if_fail (id != NULL, NULL);

	return g_strdup_printf ("%s (pptp).conf", id);
}

static guint32
get_capabilities (NMVpnPluginUiInterface *iface)
{
	return (NM_VPN_PLUGIN_UI_CAPABILITY_IMPORT | NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT);
}

static NMVpnPluginUiWidgetInterface *
ui_factory (NMVpnPluginUiInterface *iface, NMConnection *connection, GError **error)
{
	return nm_vpn_plugin_ui_widget_interface_new (connection, error);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME:
		g_value_set_string (value, PPTP_PLUGIN_NAME);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC:
		g_value_set_string (value, PPTP_PLUGIN_DESC);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE:
		g_value_set_string (value, PPTP_PLUGIN_SERVICE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
pptp_plugin_ui_class_init (PptpPluginUiClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME,
									  NM_VPN_PLUGIN_UI_INTERFACE_NAME);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC,
									  NM_VPN_PLUGIN_UI_INTERFACE_DESC);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE,
									  NM_VPN_PLUGIN_UI_INTERFACE_SERVICE);
}

static void
pptp_plugin_ui_init (PptpPluginUi *plugin)
{
}

static void
pptp_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class)
{
	/* interface implementation */
	iface_class->ui_factory = ui_factory;
	iface_class->get_capabilities = get_capabilities;
	iface_class->import = import;
	iface_class->export = export;
	iface_class->get_suggested_name = get_suggested_name;
	iface_class->delete_connection = delete_connection;
}


G_MODULE_EXPORT NMVpnPluginUiInterface *
nm_vpn_plugin_ui_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return NM_VPN_PLUGIN_UI_INTERFACE (g_object_new (PPTP_TYPE_PLUGIN_UI, NULL));
}

