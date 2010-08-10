/*
 *	Copyright (C) Elvis Pfützenreuter, 2000
 *	Copyright © Jan Engelhardt, 2006 - 2009
 *	Copyright © Bastian Kleineidam, 2005
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <sys/types.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libHX/defs.h>
#include <libHX/deque.h>
#include <libHX/list.h>
#include <libHX/map.h>
#include <pwd.h>
#include "pam_mount.h"

/**
 * allow_ok - check for disallowed options
 * @allowed:	list of allowed options
 * @options:	options to check
 *
 * Check if there are any options in @options that are not in @allowed.
 * If so, return false.
 */
static bool allow_ok(const struct HXmap *allowed,
    const struct HXclist_head *options)
{
	const struct kvp *kvp;

	if (HXmap_find(allowed, "*") != NULL || options->items == 0)
		return true;

	HXlist_for_each_entry(kvp, options, list)
		if (HXmap_find(allowed, kvp->key) == NULL) {
			l0g("option \"%s\" not allowed\n", kvp->key);
			return false;
		}

	return true;
}

/**
 * required_ok - check for missing options
 * @required:	list of required options
 * @options:	options to check
 *
 * Checks @options whether it contains all options in @required.
 * If so, returns true.
 */
static bool required_ok(const struct HXmap *required,
    const struct HXclist_head *options)
{
	const struct HXmap_node *e;
	struct HXmap_trav *t;

	if ((t = HXmap_travinit(required, 0)) == NULL)
		return false;

	while ((e = HXmap_traverse(t)) != NULL)
		if (!kvplist_contains(options, e->key)) {
			l0g("option \"%s\" required\n",
			    static_cast(const char *, e->key));
			HXmap_travfree(t);
			return false;
		}

	HXmap_travfree(t);
	return true;
}

/**
 * deny_ok - check for denied options
 * @denied:	list of denied options
 * @options:	options to check
 *
 * Checks @options whether any of them appear in @deny. If so, returns false.
 */
static bool deny_ok(const struct HXmap *denied,
    const struct HXclist_head *options)
{
	const struct HXmap_node *e;
	struct HXmap_trav *t;

	if (denied->items == 0) {
		w4rn("no denied options\n");
		return true;
	} else if (HXmap_find(denied, "*") != NULL && options->items != 0) {
		l0g("all mount options denied, user tried to specify one\n");
		return false;
	}

	if ((t = HXmap_travinit(denied, 0)) == NULL)
		return false;

	while ((e = HXmap_traverse(t)) != NULL)
		if (kvplist_contains(options, e->key)) {
			l0g("option \"%s\" denied\n",
			    static_cast(const char *, e->key));
			HXmap_travfree(t);
			return false;
		}

	HXmap_travfree(t);
	return true;
}

/**
 * luserconf_volume_record_sane -
 * @config:	current configuration
 * @vol:	volume descriptor
 *
 * Check whether the per-user volume is in accordance with permissions
 * and option restrictions.
 */
bool luserconf_volume_record_sane(const struct config *config,
    const struct vol *vol)
{
	w4rn("checking sanity of luserconf volume record (%s)\n",
	     vol->volume);

	if (vol->type == CMD_LCLMOUNT || vol->type == CMD_CRYPTMOUNT) {
		if (strcmp(vol->fstype, "tmpfs") != 0 &&
		    !pmt_fileop_owns(config->user, vol->volume)) {
			l0g("user-defined volume (%s), volume not owned "
			    "by user\n", vol->volume);
			return false;
		}
		/*
		 * If it does not already exist then it is okay, pam_mount will
		 * mkdir it (if configured to do so)
		 */
		if (pmt_fileop_exists(vol->mountpoint) &&
		    !pmt_fileop_owns(config->user, vol->mountpoint)) {
			l0g("user-defined volume (%s), mountpoint not owned "
			    "by user\n", vol->volume);
			return false;
		}
	}

	if (!vol->use_fstab) {
		if (!required_ok(config->options_require, &vol->options)) {
			misc_log("Luser volume for %s is missing options that "
			         "are required by global <mntoptions>\n",
			         vol->mountpoint);
			return false;
		}
		if (config->options_allow->items != 0 &&
		    !allow_ok(config->options_allow, &vol->options)) {
			misc_log("Luser volume for %s has options that are "
			         "not allowed per global <mntoptions>\n",
			         vol->mountpoint);
			return false;
		}
		if (config->options_deny->items != 0 &&
		    !deny_ok(config->options_deny, &vol->options)) {
			misc_log("Luser volume for %s has options that are "
			         "denied by global <mntoptions>\n",
			         vol->mountpoint);
			return false;
		}
	}

	return true;
}

/**
 * volume_record_sane -
 * @config:	current configuration
 * @vpt:	volume descriptor
 *
 * FIXME: check to ensure input is legal and reject all else instead of
 * rejecting everyhing that is illegal.
 */
bool volume_record_sane(const struct config *config, const struct vol *vpt)
{
	if (vpt->type >= _CMD_MAX) {
		l0g("Illegal volume type %u (max is %u)\n",
		    vpt->type, _CMD_MAX - 1);
		return false;
	}
	if (config->command[vpt->type]->items == 0) {
		l0g("mount command not defined for this type\n");
		return false;
	}
	if (vpt->type == CMD_SMBMOUNT || vpt->type == CMD_CIFSMOUNT ||
	    vpt->type == CMD_NCPMOUNT || vpt->type == CMD_NFSMOUNT)
		if (vpt->server == NULL || strlen(vpt->server) == 0) {
			l0g("remote mount type specified without server\n");
			return false;
		}
	if (vpt->volume == NULL) {
		l0g("volume source is not defined\n");
		return false;
	}

	if (config->command[CMD_UMOUNT]->items == 0) {
		l0g("umount command not defined\n");
		return false;
	}
	if ((vpt->fs_key_cipher != NULL && strlen(vpt->fs_key_cipher) > 0) &&
	    (vpt->fs_key_path == NULL || strlen(vpt->fs_key_path) == 0)) {
		l0g("fs_key_cipher defined without fs_key_path\n");
		return false;
	}
	if ((vpt->fs_key_cipher == NULL || strlen(vpt->fs_key_cipher) == 0) &&
	    (vpt->fs_key_path != NULL && strlen(vpt->fs_key_path) > 0)) {
		l0g("fs_key_path defined without fs_key_cipher\n");
		return false;
	}
	return true;
}
