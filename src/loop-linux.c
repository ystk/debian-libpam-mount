/*
 *	Copyright Jan Engelhardt, 2008
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include "config.h"
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include "libcryptmount.h"
#include "pam_mount.h"

#ifdef HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME
#include <linux/loop.h>

/*
 * This needs to be the max minor over all time,
 * even if older systems have less.
 */
static const unsigned int LINUX_MAX_MINOR = 1 << 20;

EXPORT_SYMBOL int ehd_loop_setup(const char *filename, char **result, bool ro)
{
	struct loop_info64 info;
	const char *dev_prefix;
	unsigned int i = 0;
	struct stat sb;
	int filefd, loopfd, ret = 0;
	char dev[64];

	*result = NULL;

	if (stat("/dev/loop0", &sb) == 0)
		dev_prefix = "/dev/loop";
	else if (stat("/dev/loop/0", &sb) == 0)
		dev_prefix = "/dev/loop/";
	else
		return ret;

	if ((filefd = open(filename, O_RDWR)) < 0)
		return -errno;

	for (i = 0; i < LINUX_MAX_MINOR; ++i) {
		snprintf(dev, sizeof(dev), "%s%u", dev_prefix, i);
		loopfd = open(dev, (ro ? O_RDONLY : O_RDWR) | O_EXCL);
		if (loopfd < 0) {
			if (errno == ENOENT)
				/* Assume we already went past the last device */
				break;
			if (errno == EPERM || errno == EACCES)
				/*
				 * Note error and try other devices
				 * before bailing out later.
				 */
				ret = -errno;
			continue;
		}
		if (ioctl(loopfd, LOOP_GET_STATUS64, &info) >= 0 ||
		    errno != ENXIO) {
			close(loopfd);
			continue;
		}
		memset(&info, 0, sizeof(info));
		strncpy(signed_cast(char *, info.lo_file_name),
		        filename, LO_NAME_SIZE);
		if (ioctl(loopfd, LOOP_SET_FD, filefd) < 0) {
			close(loopfd);
			continue;
		}
		ioctl(loopfd, LOOP_SET_STATUS64, &info);
		close(loopfd);
		*result = HX_strdup(dev);
		if (*result == NULL)
			ret = -ENOMEM;
		else
			ret = 1;
		break;
	}

	close(filefd);
	return ret;
}

EXPORT_SYMBOL int ehd_loop_release(const char *device)
{
	static const struct timespec wait_time = {0, 200000000};
	unsigned int count = 50;
	int loopfd, ret;

	if ((loopfd = open(device, O_RDONLY)) < 0)
		return -errno;
	do {
		/*
		 * Oh yeah this interface sucks. There is no guarantee we
		 * are the authoritative holder for the loop device.
		 */
		if (ioctl(loopfd, LOOP_CLR_FD) >= 0) {
			ret = 1;
			break;
		}
		ret = -errno;
		nanosleep(&wait_time, NULL);
	} while (--count > 0);
	close(loopfd);
	return ret;
}

#endif /* HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME */
