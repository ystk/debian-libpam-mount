/*
 *	Copyright © Jan Engelhardt, 2008
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include "config.h"

/**
 * pmt_loop_setup - associate file to a loop device
 * @filename:	file to associate
 * @result:	result buffer for path to loop device
 * @ro:		readonly
 *
 * Returns -errno on error, or positive on success,
 * zero when no devices were available.
 */
#if defined(HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME) || \
    defined(HAVE_SYS_MDIOCTL_H) || defined(HAVE_DEV_VNDVAR_H)
	/* elsewhere */
#else
int pmt_loop_setup(const char *filename, char **result, bool ro)
{
	fprintf(stderr, "%s: no pam_mount support for loop devices "
	        "on this platform\n", __func__);
	return -ENOSYS;
}
#endif

/**
 * pmt_loop_release - release a loop device
 * @device:	loop node
 */
#if defined(HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME) || \
    defined(HAVE_SYS_MDIOCTL_H) || defined(HAVE_DEV_VNDVAR_H)
	/* elsewhere */
#else
int pmt_loop_release(const char *device)
{
	return -ENOSYS;
}
#endif
