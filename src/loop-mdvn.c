/*
 *	FreeBSD loop device support
 *	Copyright Jan Engelhardt, 2009
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <sys/mdioctl.h>
#include "libcryptmount.h"
#include "pam_mount.h"

EXPORT_SYMBOL int ehd_loop_setup(const char *filename, char **result, bool ro)
{
	struct stat sb;
	struct md_ioctl info = {
		.md_version = MDIOVERSION,
		.md_type    = MD_VNODE,
		.md_options = MD_CLUSTER | MD_AUTOUNIT | MD_COMPRESS |
		              (ro ? MD_READONLY : 0),
		.md_file    = const_cast1(char *, filename),
	};
	int ret, fd;

	if (stat(filename, &sb) < 0)
		return -errno;
	info.md_mediasize = sb.st_size;

	if ((fd = open("/dev/" MDCTL_NAME, O_RDWR)) < 0)
		return -errno;
	if ((ret = ioctl(fd, MDIOCATTACH, &info)) == 0) {
		char buf[64];
		snprintf(buf, sizeof(buf), "/dev/" MD_NAME "%u", info.md_unit);
		*result = HX_strdup(buf);
		ret = 1;
	} else {
		ret = -errno;
	}
	close(fd);
	return ret;
}

EXPORT_SYMBOL int ehd_loop_release(const char *device)
{
	struct md_ioctl info = {.md_version = MDIOVERSION};
	int ret, fd;
	char *end;

	if (strncmp(device, "/dev/", 5) == 0)
		device += 5;
	if (strncmp(device, "md", 2) == 0)
		device += 2;
	info.md_unit = strtol(device, &end, 0);
	if (device == end || *end != '\0')
		return -ENXIO;

	if ((fd = open("/dev/" MDCTL_NAME, O_RDWR)) < 0)
		return -errno;
	if (ioctl(fd, MDIOCDETACH, &info) < 0)
		ret = -errno;
	else
		ret = 1;
	close(fd);
	return ret;
}
