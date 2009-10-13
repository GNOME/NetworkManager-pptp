/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>
#include <glib/gi18n-lib.h>
#include <glade/glade.h>

#include <nm-connection.h>
#include <nm-setting-vpn.h>

#include "advanced-dialog.h"
#include "nm-pptp.h"
#include "../src/nm-pptp-service.h"

#define COL_NAME  0
#define COL_VALUE 1
#define COL_TAG 2

#define TAG_PAP      0
#define TAG_CHAP     1
#define TAG_MSCHAP   2
#define TAG_MSCHAPV2 3
#define TAG_EAP      4

static const char *advanced_keys[] = {
	NM_PPTP_KEY_REFUSE_EAP,
	NM_PPTP_KEY_REFUSE_PAP,
	NM_PPTP_KEY_REFUSE_CHAP,
	NM_PPTP_KEY_REFUSE_MSCHAP,
	NM_PPTP_KEY_REFUSE_MSCHAPV2,
	NM_PPTP_KEY_REQUIRE_MPPE,
	NM_PPTP_KEY_REQUIRE_MPPE_40,
	NM_PPTP_KEY_REQUIRE_MPPE_128,
	NM_PPTP_KEY_MPPE_STATEFUL,
	NM_PPTP_KEY_NOBSDCOMP,
	NM_PPTP_KEY_NODEFLATE,
	NM_PPTP_KEY_NO_VJ_COMP,
	NM_PPTP_KEY_LCP_ECHO_FAILURE,
	NM_PPTP_KEY_LCP_ECHO_INTERVAL,
	NULL
};

static void
copy_values (const char *key, const char *value, gpointer user_data)
{
	GHashTable *hash = (GHashTable *) user_data;
	const char **i;

	for (i = &advanced_keys[0]; *i; i++) {
		if (strcmp (key, *i))
			continue;
		g_hash_table_insert (hash, g_strdup (key), g_strdup (value));
	}
}

GHashTable *
advanced_dialog_new_hash_from_connection (NMConnection *connection,
                                          GError **error)
{
	GHashTable *hash;
	NMSettingVPN *s_vpn;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	nm_setting_vpn_foreach_data_item (s_vpn, copy_values, hash);
	return hash;
}

static void
mppe_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GladeXML *xml = (GladeXML *) user_data;
	GtkWidget *widget;
	gboolean use_mppe;

	use_mppe = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check));

	widget = glade_xml_get_widget (xml, "ppp_mppe_security_label");
	gtk_widget_set_sensitive (widget, use_mppe);

	widget = glade_xml_get_widget (xml, "ppp_mppe_security_combo");
	if (!use_mppe)
		gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0); /* default */
	gtk_widget_set_sensitive (widget, use_mppe);

	widget = glade_xml_get_widget (xml, "ppp_allow_stateful_mppe");
	if (!use_mppe)
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);
	gtk_widget_set_sensitive (widget, use_mppe);
}

#define SEC_INDEX_DEFAULT   0
#define SEC_INDEX_MPPE_128  1
#define SEC_INDEX_MPPE_40   2

static void
setup_security_combo (GladeXML *xml, GHashTable *hash)
{
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	int active = -1;
	const char *value;

	g_return_if_fail (xml != NULL);
	g_return_if_fail (hash != NULL);

	widget = glade_xml_get_widget (xml, "ppp_mppe_security_combo");

	store = gtk_list_store_new (1, G_TYPE_STRING);

	/* Default (allow use of all encryption types that both server and client support) */
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("All Available (Default)"), -1);

	/* MPPE-128 */
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("128-bit (most secure)"), -1);
	if (active < 0) {
		value = g_hash_table_lookup (hash, NM_PPTP_KEY_REQUIRE_MPPE_128);
		if (value && !strcmp (value, "yes"))
			active = SEC_INDEX_MPPE_128;
	}

	/* MPPE-40 */
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("40-bit (less secure)"), -1);
	if (active < 0) {
		value = g_hash_table_lookup (hash, NM_PPTP_KEY_REQUIRE_MPPE_40);
		if (value && !strcmp (value, "yes"))
			active = SEC_INDEX_MPPE_40;
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? SEC_INDEX_DEFAULT : active);
}

static void
check_toggled_cb (GtkCellRendererToggle *cell, gchar *path_str, gpointer user_data)
{
	GladeXML *xml = GLADE_XML (user_data);
	GtkWidget *widget;
	GtkTreePath *path = gtk_tree_path_new_from_string (path_str);
	GtkTreeModel *model;
	GtkTreeIter iter;
	gboolean toggle_item;

	widget = glade_xml_get_widget (xml, "ppp_auth_methods");
	model = gtk_tree_view_get_model (GTK_TREE_VIEW (widget));

	gtk_tree_model_get_iter (model, &iter, path);
	gtk_tree_model_get (model, &iter, COL_VALUE, &toggle_item, -1);

	toggle_item ^= 1;

	/* set new value */
	gtk_list_store_set (GTK_LIST_STORE (model), &iter, COL_VALUE, toggle_item, -1);

	gtk_tree_path_free (path);
}

static void
auth_methods_setup (GladeXML *xml, GHashTable *hash)
{
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	const char *value;
	gboolean allowed;
	gboolean use_mppe = FALSE;
	GtkCellRendererToggle *check_renderer;
	GtkCellRenderer *text_renderer;
	GtkTreeViewColumn *column;
	gint offset;

	store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_UINT);

	/* Check for MPPE */
	value = g_hash_table_lookup (hash, NM_PPTP_KEY_REQUIRE_MPPE);
	if (value && !strcmp (value, "yes"))
		use_mppe = TRUE;
	
	/* Or MPPE-128 */
	value = g_hash_table_lookup (hash, NM_PPTP_KEY_REQUIRE_MPPE_128);
	if (value && !strcmp (value, "yes"))
		use_mppe = TRUE;

	/* Or MPPE-40 */
	value = g_hash_table_lookup (hash, NM_PPTP_KEY_REQUIRE_MPPE_40);
	if (value && !strcmp (value, "yes"))
		use_mppe = TRUE;

	/* PAP */
	value = g_hash_table_lookup (hash, NM_PPTP_KEY_REFUSE_PAP);
	allowed = (value && !strcmp (value, "yes")) ? FALSE : TRUE;
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, COL_NAME, _("PAP"), COL_VALUE, allowed, COL_TAG, TAG_PAP, -1);

	/* CHAP */
	value = g_hash_table_lookup (hash, NM_PPTP_KEY_REFUSE_CHAP);
	allowed = (value && !strcmp (value, "yes")) ? FALSE : TRUE;
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, COL_NAME, _("CHAP"), COL_VALUE, allowed, COL_TAG, TAG_CHAP, -1);

	/* MSCHAP */
	value = g_hash_table_lookup (hash, NM_PPTP_KEY_REFUSE_MSCHAP);
	allowed = (value && !strcmp (value, "yes")) ? FALSE : TRUE;
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, COL_NAME, _("MSCHAP"), COL_VALUE, allowed, COL_TAG, TAG_MSCHAP, -1);

	/* MSCHAPv2 */
	value = g_hash_table_lookup (hash, NM_PPTP_KEY_REFUSE_MSCHAPV2);
	allowed = (value && !strcmp (value, "yes")) ? FALSE : TRUE;
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, COL_NAME, _("MSCHAPv2"), COL_VALUE, allowed, COL_TAG, TAG_MSCHAPV2, -1);

	/* EAP */
	value = g_hash_table_lookup (hash, NM_PPTP_KEY_REFUSE_EAP);
	allowed = (value && !strcmp (value, "yes")) ? FALSE : TRUE;
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, COL_NAME, _("EAP"), COL_VALUE, allowed, COL_TAG, TAG_EAP, -1);

	/* Set up the tree view */
	widget = glade_xml_get_widget (xml, "ppp_auth_methods");
	gtk_tree_view_set_model (GTK_TREE_VIEW (widget), GTK_TREE_MODEL (store));

	check_renderer = GTK_CELL_RENDERER_TOGGLE (gtk_cell_renderer_toggle_new ());
	g_signal_connect (check_renderer, "toggled", G_CALLBACK (check_toggled_cb), xml);

	offset = gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (widget),
	                                                      -1, "", GTK_CELL_RENDERER (check_renderer),
	                                                      "active", COL_VALUE,
	                                                      NULL);
	column = gtk_tree_view_get_column (GTK_TREE_VIEW (widget), offset - 1);
	gtk_tree_view_column_set_sizing (GTK_TREE_VIEW_COLUMN (column), GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_fixed_width (GTK_TREE_VIEW_COLUMN (column), 30);
	gtk_tree_view_column_set_clickable (GTK_TREE_VIEW_COLUMN (column), TRUE);

	text_renderer = gtk_cell_renderer_text_new ();
	offset = gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (widget),
	                                                      -1, "", text_renderer,
	                                                      "text", COL_NAME,
	                                                      NULL);
	column = gtk_tree_view_get_column (GTK_TREE_VIEW (widget), offset - 1);
	gtk_tree_view_column_set_expand (GTK_TREE_VIEW_COLUMN (column), TRUE);
}

GtkWidget *
advanced_dialog_new (GHashTable *hash)
{
	GladeXML *xml;
	GtkWidget *dialog = NULL;
	char *glade_file = NULL;
	GtkWidget *widget;
	const char *value;

	g_return_val_if_fail (hash != NULL, NULL);

	glade_file = g_strdup_printf ("%s/%s", GLADEDIR, "nm-pptp-dialog.glade");
	xml = glade_xml_new (glade_file, "pptp-advanced-dialog", GETTEXT_PACKAGE);
	if (xml == NULL)
		goto out;

	dialog = glade_xml_get_widget (xml, "pptp-advanced-dialog");
	if (!dialog) {
		g_object_unref (G_OBJECT (xml));
		goto out;
	}
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);

	g_object_set_data_full (G_OBJECT (dialog), "glade-xml",
	                        xml, (GDestroyNotify) g_object_unref);

	setup_security_combo (xml, hash);

	widget = glade_xml_get_widget (xml, "ppp_use_mppe");
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (mppe_toggled_cb), xml);

	value = g_hash_table_lookup (hash, NM_PPTP_KEY_REQUIRE_MPPE);
	if (value && !strcmp (value, "yes"))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	mppe_toggled_cb (widget, xml);

	widget = glade_xml_get_widget (xml, "ppp_allow_stateful_mppe");
	value = g_hash_table_lookup (hash, NM_PPTP_KEY_MPPE_STATEFUL);
	if (value && !strcmp (value, "yes"))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

	widget = glade_xml_get_widget (xml, "ppp_allow_bsdcomp");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	value = g_hash_table_lookup (hash, NM_PPTP_KEY_NOBSDCOMP);
	if (value && !strcmp (value, "yes"))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

	widget = glade_xml_get_widget (xml, "ppp_allow_deflate");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	value = g_hash_table_lookup (hash, NM_PPTP_KEY_NODEFLATE);
	if (value && !strcmp (value, "yes"))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

	widget = glade_xml_get_widget (xml, "ppp_usevj");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	value = g_hash_table_lookup (hash, NM_PPTP_KEY_NO_VJ_COMP);
	if (value && !strcmp (value, "yes"))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

	widget = glade_xml_get_widget (xml, "ppp_send_echo_packets");
	value = g_hash_table_lookup (hash, NM_PPTP_KEY_LCP_ECHO_INTERVAL);
	if (value && strlen (value)) {
		long int tmp_int;

		errno = 0;
		tmp_int = strtol (value, NULL, 10);
		if (errno == 0 && tmp_int > 0)
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	}

	auth_methods_setup (xml, hash);

out:
	g_free (glade_file);
	return dialog;
}

GHashTable *
advanced_dialog_new_hash_from_dialog (GtkWidget *dialog, GError **error)
{
	GHashTable *hash;
	GtkWidget *widget;
	GladeXML *xml;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gboolean valid;

	g_return_val_if_fail (dialog != NULL, NULL);
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	xml = g_object_get_data (G_OBJECT (dialog), "glade-xml");
	g_return_val_if_fail (xml != NULL, NULL);

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	widget = glade_xml_get_widget (xml, "ppp_use_mppe");
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {

		widget = glade_xml_get_widget (xml, "ppp_mppe_security_combo");
		switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget))) {
		case SEC_INDEX_MPPE_128:
			g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_REQUIRE_MPPE_128), g_strdup ("yes"));
			break;
		case SEC_INDEX_MPPE_40:
			g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_REQUIRE_MPPE_40), g_strdup ("yes"));
			break;
		default:
			g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_REQUIRE_MPPE), g_strdup ("yes"));
			break;
		}

		widget = glade_xml_get_widget (xml, "ppp_allow_stateful_mppe");
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
			g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_MPPE_STATEFUL), g_strdup ("yes"));
	}

	widget = glade_xml_get_widget (xml, "ppp_allow_bsdcomp");
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_NOBSDCOMP), g_strdup ("yes"));

	widget = glade_xml_get_widget (xml, "ppp_allow_deflate");
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_NODEFLATE), g_strdup ("yes"));

	widget = glade_xml_get_widget (xml, "ppp_usevj");
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_NO_VJ_COMP), g_strdup ("yes"));

	widget = glade_xml_get_widget (xml, "ppp_send_echo_packets");
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_LCP_ECHO_FAILURE), g_strdup_printf ("%d", 5));
		g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_LCP_ECHO_INTERVAL), g_strdup_printf ("%d", 30));
	}

	widget = glade_xml_get_widget (xml, "ppp_auth_methods");
	model = gtk_tree_view_get_model (GTK_TREE_VIEW (widget));
	valid = gtk_tree_model_get_iter_first (model, &iter);
	while (valid) {
		gboolean allowed;
		guint32 tag;

		gtk_tree_model_get (model, &iter, COL_VALUE, &allowed, COL_TAG, &tag, -1);
		switch (tag) {
		case TAG_PAP:
			if (!allowed)
				g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_REFUSE_PAP), g_strdup ("yes"));
			break;
		case TAG_CHAP:
			if (!allowed)
				g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_REFUSE_CHAP), g_strdup ("yes"));
			break;
		case TAG_MSCHAP:
			if (!allowed)
				g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_REFUSE_MSCHAP), g_strdup ("yes"));
			break;
		case TAG_MSCHAPV2:
			if (!allowed)
				g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_REFUSE_MSCHAPV2), g_strdup ("yes"));
			break;
		case TAG_EAP:
			if (!allowed)
				g_hash_table_insert (hash, g_strdup (NM_PPTP_KEY_REFUSE_EAP), g_strdup ("yes"));
			break;
		default:
			break;
		}

		valid = gtk_tree_model_iter_next (model, &iter);
	}

	return hash;
}

