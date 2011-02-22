/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>

#include <nm-setting-vpn.h>
#include <nm-vpn-plugin-utils.h>

#include "src/nm-pptp-service.h"
#include "common-gnome/keyring-helpers.h"
#include "gnome-two-password-dialog.h"

static gboolean
get_secrets (const char *vpn_uuid,
             const char *vpn_name,
             gboolean retry,
             gboolean allow_interaction,
             const char *in_pw,
             char **out_pw,
             NMSettingSecretFlags pw_flags)
{
	GnomeTwoPasswordDialog *dialog;
	gboolean is_session = TRUE;
	char *prompt, *pw = NULL;

	g_return_val_if_fail (vpn_uuid != NULL, FALSE);
	g_return_val_if_fail (vpn_name != NULL, FALSE);
	g_return_val_if_fail (out_pw != NULL, FALSE);
	g_return_val_if_fail (*out_pw == NULL, FALSE);

	/* Get the existing secret, if any */
	if (   !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
	    && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
		if (in_pw)
			pw = gnome_keyring_memory_strdup (in_pw);
		else
			pw = keyring_helpers_lookup_secret (vpn_uuid, NM_PPTP_KEY_PASSWORD, &is_session);
	}

	/* Don't ask if the passwords is unused */
	if (pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED) {
		gnome_keyring_memory_free (pw);
		return TRUE;
	}

	if (!retry) {
		/* Don't ask the user if we don't need a new password (ie, !retry),
		 * we have an existing PW, and the password is saved.
		 */
		if (pw && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			*out_pw = pw;
			return TRUE;
		}
	}

	/* If interaction isn't allowed, just return existing secrets */
	if (allow_interaction == FALSE) {
		*out_pw = pw;
		return TRUE;
	}

	/* Otherwise, we have no saved password, or the password flags indicated
	 * that the password should never be saved.
	 */
	prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network '%s'."), vpn_name);
	dialog = GNOME_TWO_PASSWORD_DIALOG (gnome_two_password_dialog_new (_("Authenticate VPN"), prompt, NULL, NULL, FALSE));
	g_free (prompt);

	gnome_two_password_dialog_set_show_username (dialog, FALSE);
	gnome_two_password_dialog_set_show_userpass_buttons (dialog, FALSE);
	gnome_two_password_dialog_set_show_domain (dialog, FALSE);
	gnome_two_password_dialog_set_show_remember (dialog, TRUE);
	gnome_two_password_dialog_set_show_password_secondary (dialog, FALSE);

	/* If nothing was found in the keyring, default to not remembering any secrets */
	if (pw) {
		/* Otherwise set default remember based on which keyring the secrets were found in */
		if (is_session)
			gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION);
		else
			gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER);
	} else
		gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_NOTHING);

	/* pre-fill dialog with the password */
	if (pw && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
		gnome_two_password_dialog_set_password (dialog, pw);

	gtk_widget_show (GTK_WIDGET (dialog));

	if (gnome_two_password_dialog_run_and_block (dialog)) {
		const char *keyring = NULL;
		gboolean save = FALSE;

		*out_pw = gnome_two_password_dialog_get_password (dialog);

		switch (gnome_two_password_dialog_get_remember (dialog)) {
		case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION:
			keyring = "session";
			/* Fall through */
		case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER:
			save = TRUE;
			break;
		default:
			break;
		}

		if (save && (pw_flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED)) {
		    if (*out_pw && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
				keyring_helpers_save_secret (vpn_uuid, vpn_name, keyring, NM_PPTP_KEY_PASSWORD, *out_pw);
			else {
				/* Clear the password from the keyring */
				keyring_helpers_delete_secret (vpn_uuid, NM_PPTP_KEY_PASSWORD);
			}
		}
	}

	gtk_widget_hide (GTK_WIDGET (dialog));
	gtk_widget_destroy (GTK_WIDGET (dialog));

	return TRUE;
}

static void
wait_for_quit (void)
{
	GString *str;
	char c;
	ssize_t n;
	time_t start;

	str = g_string_sized_new (10);
	start = time (NULL);
	do {
		errno = 0;
		n = read (0, &c, 1);
		if (n == 0 || (n < 0 && errno == EAGAIN))
			g_usleep (G_USEC_PER_SEC / 10);
		else if (n == 1) {
			g_string_append_c (str, c);
			if (strstr (str->str, "QUIT") || (str->len > 10))
				break;
		} else
			break;
	} while (time (NULL) < start + 20);
	g_string_free (str, TRUE);
}

int 
main (int argc, char *argv[])
{
	gboolean retry = FALSE, allow_interaction = FALSE;
	char *vpn_name = NULL, *vpn_uuid = NULL, *vpn_service = NULL, *password = NULL;
	GHashTable *data = NULL, *secrets = NULL;
	NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;
	GOptionContext *context;
	GOptionEntry entries[] = {
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
			{ "allow-interaction", 'i', 0, G_OPTION_ARG_NONE, &allow_interaction, "Allow user interaction", NULL},
			{ NULL }
		};

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	gtk_init (&argc, &argv);

	context = g_option_context_new ("- pptp auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
	g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);

	if (!vpn_uuid || !vpn_service || !vpn_name) {
		fprintf (stderr, "A connection UUID, name, and VPN plugin service name are required.\n");
		return 1;
	}

	if (strcmp (vpn_service, NM_DBUS_SERVICE_PPTP) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_DBUS_SERVICE_PPTP);
		return 1;
	}

	if (!nm_vpn_plugin_utils_read_vpn_details (0, &data, &secrets)) {
		fprintf (stderr, "Failed to read '%s' (%s) data and secrets from stdin.\n",
		         vpn_name, vpn_uuid);
		return 1;
	}

	nm_vpn_plugin_utils_get_secret_flags (secrets, NM_PPTP_KEY_PASSWORD, &pw_flags);

	if (!get_secrets (vpn_uuid, vpn_name, retry, allow_interaction,
	                  g_hash_table_lookup (secrets, NM_PPTP_KEY_PASSWORD),
	                  &password,
	                  pw_flags))
		return 1;

	/* dump the passwords to stdout */
	printf ("%s\n%s\n", NM_PPTP_KEY_PASSWORD, password);
	printf ("\n\n");

	if (password) {
		memset (password, 0, strlen (password));
		gnome_keyring_memory_free (password);
	}

	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	/* Wait for quit signal */
	wait_for_quit ();

	if (data)
		g_hash_table_unref (data);
	if (secrets)
		g_hash_table_unref (secrets);
	return 0;
}
