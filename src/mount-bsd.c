/*
 *	Copyright © Jan Engelhardt, 2007 - 2008
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include "config.h"
#if !defined(HAVE_GETMNTENT) && defined(HAVE_GETMNTINFO) /* entire file */

#ifdef HAVE_SYS_MOUNT_H
#	include <sys/mount.h>
#endif
#ifdef HAVE_SYS_STATVFS_H
#	include <sys/statvfs.h>
#endif
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <libHX/string.h>
#include "pam_mount.h"

#if defined(__FreeBSD__)
#	define local_statfs statfs
#	define LOCAL_NOWAIT MNT_NOWAIT
#elif defined(__NetBSD__)
#	define local_statfs statvfs
#	define LOCAL_NOWAIT ST_NOWAIT
#endif

int pmt_already_mounted(const struct config *config,
    const struct vol *vpt, struct HXformat_map *vinfo)
{
	hxmc_t *dev;
	bool mounted = false;
	struct local_statfs *mntbuf;
	int num_mounts, i;

	if ((num_mounts = getmntinfo(&mntbuf, LOCAL_NOWAIT)) <= 0) {
		l0g("getmntinfo: %s\n", strerror(errno));
		return -1;
	}

	if ((dev = pmt_vol_to_dev(vpt)) == NULL) {
		l0g("pmt::vol_to_dev: %s\n", strerror(errno));
		return -1;
	}

	for (i = 0; i < num_mounts; ++i) {
		const struct local_statfs *mnt = &mntbuf[i];
		int (*xcmp)(const char *, const char *);

		xcmp = fstype_icase(mnt->f_fstypename) ?
		       strcasecmp : strcmp;

		/*
		 * FIXME: Does BSD also turn "symlink mountpoints" into "real
		 * mountpoints"?
		 */
		if (xcmp(mnt->f_mntfromname, dev) == 0 &&
		    strcmp(mnt->f_mntonname, vpt->mountpoint) == 0) {
			mounted = 1;
			break;
		}
	}

	HXmc_free(dev);
	return mounted || pmt_cmtab_mounted(dev, vpt->mountpoint);
}

#endif /* !HAVE_GETMNTENT && HAVE_GETMNTINFO */
