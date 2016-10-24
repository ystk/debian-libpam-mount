/*
 *	Copyright Jan Engelhardt, 2006 - 2009
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>
#include "libcryptmount.h"
#include "pam_mount.h"

static unsigned int ehd_log_ft[__EHD_LOGFT_MAX];

EXPORT_SYMBOL int ehd_logctl(enum ehd_log_feature ft, ...)
{
	va_list ap;
	va_start(ap, ft);
	int a = va_arg(ap, int);

	if (a == EHD_LOG_GET) {
		return ehd_log_ft[ft];
	} else if (a == EHD_LOG_SET) {
		++ehd_log_ft[ft];
	} else if (a == EHD_LOG_UNSET) {
		if (ehd_log_ft[ft] == 0)
			fprintf(stderr, "%s: feature %u is already zero\n",
			        __func__, ft);
		else
			--ehd_log_ft[ft];
	}
	return 1;
}

/**
 * ehd_err - log an error/warning
 * @format:	printf(3)-style format specifier
 */
EXPORT_SYMBOL int ehd_err(const char *format, ...)
{
	va_list args, arg2;
	int ret = 0;

	assert(format != NULL);

	if (!ehd_log_ft[EHD_LOGFT_NOSYSLOG]) {
		va_start(args, format);
		va_copy(arg2, args);
		vsyslog(LOG_AUTH | LOG_ERR, format, arg2);
		va_end(arg2);
	}
	ret = vfprintf(stderr, format, args);
	va_end(args);
	return ret;
}

/**
 * ehd_dbg - log informational messages
 * @format:	printf(3)-style format specifier
 *
 * If debugging is turned on, the message is logged to syslog and %stderr.
 * Use this for debugging messages.
 *
 * Do not call this function directly; use the w4rn() macro instead, so that
 * file name and line number show up.
 */
EXPORT_SYMBOL int ehd_dbg(const char *format, ...)
{
	va_list args, arg2;
	int ret = 0;

	assert(format != NULL);
	if (!ehd_log_ft[EHD_LOGFT_DEBUG])
		return 0;

	va_start(args, format);
	if (!ehd_log_ft[EHD_LOGFT_NOSYSLOG]) {
		va_copy(arg2, args);
		vsyslog(LOG_AUTH | LOG_ERR, format, arg2);
		va_end(arg2);
	}
	ret = vfprintf(stderr, format, args);
	va_end(args);
	return ret;
}
