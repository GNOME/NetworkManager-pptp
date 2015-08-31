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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#ifndef NM_PPTP_PLUGIN_H
#define NM_PPTP_PLUGIN_H

#include <glib.h>
#include <glib-object.h>
#include <NetworkManager.h>
#include <nm-vpn-service-plugin.h>

#include "nm-pptp-service-defines.h"

#define NM_TYPE_PPTP_PLUGIN            (nm_pptp_plugin_get_type ())
#define NM_PPTP_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PPTP_PLUGIN, NMPptpPlugin))
#define NM_PPTP_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_PPTP_PLUGIN, NMPptpPluginClass))
#define NM_IS_PPTP_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_PPTP_PLUGIN))
#define NM_IS_PPTP_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_PPTP_PLUGIN))
#define NM_PPTP_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_PPTP_PLUGIN, NMPptpPluginClass))

/* For the pppd plugin <-> VPN plugin service */
#define DBUS_TYPE_G_MAP_OF_VARIANT (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE))

typedef struct {
	NMVpnServicePlugin parent;
} NMPptpPlugin;

typedef struct {
	NMVpnServicePluginClass parent;
} NMPptpPluginClass;

GType nm_pptp_plugin_get_type (void);

NMPptpPlugin *nm_pptp_plugin_new (void);

#endif /* NM_PPTP_PLUGIN_H */
