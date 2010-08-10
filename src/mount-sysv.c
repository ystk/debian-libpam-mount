/*
 *	Copyright © Jan Engelhardt, 2007 - 2009
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include "config.h"
#ifdef HAVE_GETMNTENT
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "pam_mount.h"

int pmt_already_mounted(const struct config *const config,
    const struct vol *vpt, struct HXformat_map *vinfo)
{
	int (*xcmp)(const char *, const char *);
	hxmc_t *dev;
	int cret, sret;

	if ((dev = pmt_vol_to_dev(vpt)) == NULL) {
		l0g("pmt::vol_to_dev: %s\n", strerror(errno));
		return -1;
	}

	xcmp = fstype2_icase(vpt->type) ? strcasecmp : strcmp;

	cret = pmt_cmtab_mounted(dev, vpt->mountpoint);
	sret = pmt_smtab_mounted(dev, vpt->mountpoint, xcmp);
	if (cret > 0 || sret > 0)
		return true;
	if (cret == 0 && sret == 0)
		return false;
	if (sret < 0)
		return sret;
	if (cret < 0)
		return cret;
	return false;
}
#endif /* HAVE_GETMNTENT */
