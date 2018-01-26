/*
 * Copyright (C) 2018 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#ifndef VHOST_H
#define VHOST_H

/* Virtual host entries; common between main and sec-mod */
#include <config.h>
#include "tlslib.h"

#define MAX_PIN_SIZE GNUTLS_PKCS11_MAX_PIN_LEN
typedef struct pin_st {
	char pin[MAX_PIN_SIZE];
	char srk_pin[MAX_PIN_SIZE];
} pin_st;

typedef struct vhost_cfg_st {
	struct list_node list;
	char *name;
	struct perm_cfg_st perm_config;

	tls_st creds;
	/* set to non-zero if authentication/accounting is initialized */
	unsigned auth_init;

	/* vhost is pool by itself on current implementation,
	 * but made explicit to avoid future breakage due to changes */
	void *pool;

	/* sec-mod accessed items */
	pin_st pins;
	time_t last_access; /* last reload/access of creds */
	struct config_mod_st *config_module;

	/* temporary values used during config loading
	 */
	char *acct;
	char **auth;
	size_t auth_size;
	char **eauth;
	size_t eauth_size;
	unsigned expose_iroutes;
	unsigned auto_select_group;
#ifdef HAVE_GSSAPI
	char **urlfw;
	size_t urlfw_size;
#endif
} vhost_cfg_st;

/* macros to retrieve the default vhost configuration */
#define GETVHOST(s) list_top((s)->vconfig, struct vhost_cfg_st, list)
#define GETCONFIG(s) GETVHOST(s)->perm_config.config
#define GETPCONFIG(s) (&(GETVHOST(s)->perm_config))
#define VHOSTNAME(vhost) vhost->name?vhost->name:""

#include <c-strcase.h>

/* always returns a vhost */
inline static vhost_cfg_st *find_vhost(struct list_head *vconfig, const char *name)
{
	vhost_cfg_st *vhost;
	if (name == NULL)
		return list_top(vconfig, struct vhost_cfg_st, list);
	
	list_for_each(vconfig, vhost, list) {
		if (vhost->name != NULL && c_strcasecmp(vhost->name, name) == 0)
			return vhost;
	}

	return list_top(vconfig, struct vhost_cfg_st, list);
}

#endif
