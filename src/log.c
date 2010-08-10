/*
 *	Copyright © Jan Engelhardt, 2006 - 2009
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
#include "pam_mount.h"

const char *pmtlog_prefix;
bool pmtlog_path[PMTLOG_SRCMAX][PMTLOG_DSTMAX];
unsigned int Debug = true;

/**
 * misc_log - log an error/warning
 * @format:	printf(3)-style format specifier
 *
 * Do not call this function directly; use the l0g() macro instead, so that
 * file name and line number show up.
 */
int misc_log(const char *format, ...)
{
	va_list args, arg2;
	int ret = 0;

	assert(format != NULL);

	va_start(args, format);
	va_copy(arg2, args);
	if (pmtlog_path[PMTLOG_ERR][PMTLOG_STDERR])
		ret = vfprintf(stderr, format, args);
	if (pmtlog_path[PMTLOG_ERR][PMTLOG_SYSLOG])
		vsyslog(LOG_AUTH | LOG_ERR, format, arg2);
	va_end(args);
	va_end(arg2);
	return ret;
}

/**
 * misc_warn - debug logger
 * @format:	printf(3)-style format specifier
 *
 * If debugging is turned on, the message is logged to syslog and %stderr.
 * Use this for debugging messages.
 *
 * Do not call this function directly; use the w4rn() macro instead, so that
 * file name and line number show up.
 */
int misc_warn(const char *format, ...)
{
	va_list args, arg2;
	int ret = 0;

	assert(format != NULL);
	if (!pmtlog_path[PMTLOG_DBG][PMTLOG_STDERR] &&
	    !pmtlog_path[PMTLOG_DBG][PMTLOG_SYSLOG])
		return 0;

	va_start(args, format);
	va_copy(arg2, args);
	if (pmtlog_path[PMTLOG_DBG][PMTLOG_STDERR])
		ret = vfprintf(stderr, format, args);
	if (pmtlog_path[PMTLOG_DBG][PMTLOG_SYSLOG])
		vsyslog(LOG_AUTH | LOG_ERR, format, arg2);
	va_end(args);
	va_end(arg2);
	return ret;
}
