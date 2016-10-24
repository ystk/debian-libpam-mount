/*
 *	Internal diagnostic tool to debug pmt loop.c
 *	Copyright Jan Engelhardt, 2008-2011
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libHX/init.h>
#include <libHX/string.h>
#include "libcryptmount.h"
#include "pam_mount.h"

static unsigned int al_do_usetup;

static int al_setup(const char **argv)
{
	char *dev;
	int ret;

	ret = ehd_loop_setup(argv[1], &dev, EHD_LOSETUP_RW);
	if (ret == 0) {
		fprintf(stderr, "%s: error: no free loop devices\n",
		        HX_basename(*argv));
		return EXIT_FAILURE;
	} else if (ret < 0) {
		fprintf(stderr, "%s: error: %s\n",
		        HX_basename(*argv), strerror(-ret));
		return EXIT_FAILURE;
	} else {
		printf("Loop device assigned: %s\n", dev);
	}

	free(dev);
	return EXIT_SUCCESS;
}

static int al_usetup(const char *loop_dev)
{
	int ret;

	if ((ret = ehd_loop_release(loop_dev)) < 0)
		fprintf(stderr, "warning: loop_release: %s\n", strerror(-ret));
	return EXIT_SUCCESS;
}

static bool al_get_options(int *argc, const char ***argv)
{
	static const struct HXoption options_table[] = {
		{.sh = 'u', .type = HXTYPE_NONE, .ptr = &al_do_usetup,
		 .help = "Unsetup"},
		HXOPT_AUTOHELP,
		HXOPT_TABLEEND,
	};
	if (HX_getopt(options_table, argc, argv, HXOPT_USAGEONERR) !=
	    HXOPT_ERR_SUCCESS)
		return false;
	if (*argc != 2) {
		fprintf(stderr, "Usage: %s file\n", HX_basename(**argv));
		return false;
	}
	return true;
}

int main(int argc, const char **argv)
{
	int ret;

	ret = HX_init();
	if (ret <= 0) {
		fprintf(stderr, "HX_init: %s\n", strerror(errno));
		abort();
	}

	if (!al_get_options(&argc, &argv))
		return EXIT_FAILURE;
	if (al_do_usetup)
		ret = al_usetup(argv[1]);
	else
		ret = al_setup(argv);

	HX_exit();
	return ret;
}
