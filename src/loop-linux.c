/*
 *	Copyright © Jan Engelhardt, 2008
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
#include <unistd.h>
#include <libHX/defs.h>
#include "pam_mount.h"

#ifdef HAVE_LINUX_FS_H
#include <linux/fs.h>
size_t pmt_block_getsize64(const char *path)
{
	uint64_t s;
	int fd;

	if ((fd = open(path, O_RDONLY | O_WRONLY)) < 0) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return 0;
	}

	if (ioctl(fd, BLKGETSIZE64, &s) < 0) {
		fprintf(stderr, "ioctl on %s: %s\n", path, strerror(errno));
		return 0;
	}

	close(fd);
	return s;
}
#endif /* HAVE_LINUX_FS_H */

#ifdef HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME
#include <linux/loop.h>

/*
 * This needs to be the max minor over all time,
 * even if older systems have less.
 */
static const unsigned int LINUX_MAX_MINOR = 1 << 20;

int pmt_loop_setup(const char *filename, char **result, bool ro)
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
		*result = xstrdup(dev);
		if (*result == NULL)
			ret = -ENOMEM;
		else
			ret = 1;
		break;
	}

	close(filefd);
	return ret;
}

int pmt_loop_release(const char *device)
{
	int loopfd, ret = 1;

	if ((loopfd = open(device, O_RDONLY)) < 0)
		return -errno;
	if (ioctl(loopfd, LOOP_CLR_FD) < 0)
		ret = -errno;
	close(loopfd);
	return ret;
}

#endif /* HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME */
