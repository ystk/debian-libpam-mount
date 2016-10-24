/*
 *	Copyright Jan Engelhardt, 2008
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <sys/ioctl.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#ifdef HAVE_LINUX_FS_H
#	include <linux/fs.h>
#endif
#include "pam_mount.h"

#ifdef HAVE_LINUX_FS_H
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

/* HAVE_LINUX_FS_H */
#else

size_t pmt_block_getsize64(const char *path)
{
	fprintf(stderr, "%s: pam_mount does not know how to retrieve the "
	        "size of a block device on this platform.\n", __func__);
	return 0;
}

#endif /* all-platforms */
