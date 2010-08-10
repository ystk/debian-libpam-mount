/*
 *	NetBSD loop device support
 *	Copyright © Jan Engelhardt, 2008- 2009
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libHX/defs.h>
#include "pam_mount.h"
#include <dev/vndvar.h>

/*
 * They sure do not have a lot... (4 by default),
 * but scan some more just in case.
 */
static const unsigned BSD_VND_MINORS = 16;

int pmt_loop_setup(const char *filename, char **result, bool ro)
{
	struct vnd_ioctl info;
	unsigned int i;
	int loopfd, ret = 0;
	char dev[64];

	for (i = 0; i < BSD_VND_MINORS; ++i) {
		snprintf(dev, sizeof(dev), "/dev/vnd%ud", i);
		loopfd = open(dev, O_RDWR | O_EXCL);
		if (loopfd < 0) {
			if (errno == ENOENT)
				break;
			if (errno == EPERM || errno == EACCES)
				ret = -errno;
			continue;
		}
		memset(&info, 0, sizeof(info));
		info.vnd_file = const_cast1(char *, filename);
		if (ro)
			info.vnd_flags |= VNDIOF_READONLY;
		if (ioctl(loopfd, VNDIOCSET, &info) < 0) {
			close(loopfd);
			continue;
		}
		close(loopfd);
		*result = xstrdup(dev);
		if (*result == NULL)
			ret = -ENOMEM;
		else
			ret = 1;
		break;
	}

	return ret;
}

int pmt_loop_release(const char *device)
{
	int loopfd, ret = 1;
	struct vnd_ioctl info;

	if ((loopfd = open(device, O_RDWR)) < 0)
		return -errno;
	memset(&info, 0, sizeof(info));
	info.vnd_flags |= VNDIOF_FORCE;
	if (ioctl(loopfd, VNDIOCCLR, &info) < 0)
		ret = -errno;
	close(loopfd);
	return ret;
}
