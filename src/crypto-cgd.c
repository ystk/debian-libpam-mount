/*
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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libHX/string.h>
#include "cmt-internal.h"
#include <dev/cgdvar.h>

/*
 * Not too many either (4 by default), often even
 * deactivated in GENERIC kernel.
 */
static const unsigned int BSD_CGD_MINORS = 8;

static int cgd_load(const struct ehd_mount_request *req,
    struct ehd_mount_info *mt)
{
	struct cgd_ioctl info;
	unsigned int i;
	char dev[64];
	int fd, ret = 0;

	for (i = 0; i < BSD_CGD_MINORS; ++i) {
		snprintf(dev, sizeof(dev), "/dev/cgd%ud", i);
		fd = open(dev, O_RDWR | O_EXCL);
		if (fd < 0) {
			if (errno == ENOENT)
				break;
			if (errno == EPERM || errno == EACCES)
				ret = -errno;
			continue;
		}
		memset(&info, 0, sizeof(info));
		info.ci_disk      = mt->lower_device;
		info.ci_alg       = req->fs_cipher;
		info.ci_blocksize = -1;
		info.ci_ivmethod  = "encblkno";
		info.ci_key       = req->key_data;
		info.ci_keylen    = req->key_size * 8;
		if (ioctl(fd, CGDIOCSET, &info) < 0) {
			close(fd);
			continue;
		}
		close(fd);
		if ((mt->crypto_device = HXmc_strinit(dev)) == NULL)
			ret = -ENOMEM;
		else
			ret = 1;
		break;
	}

	return ret;
}

static int cgd_unload(const struct ehd_mount_info *mt)
{
	int saved_errno, fd, ret;

	if ((fd = open(mt->crypto_device, O_RDWR)) < 0)
		return -errno;
	saved_errno = 0;
	ret = 1;
	if (ioctl(fd, CGDIOCCLR) < 0)
		ret = -(saved_errno = errno);
	close(fd);
	errno = saved_errno;
	return ret;
}

const struct ehd_crypto_ops ehd_cgd_ops = {
	.load   = cgd_load,
	.unload = cgd_unload,
};
