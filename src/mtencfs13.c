/*
 *	mount.encfs13
 *	Small mount wrapper for encfs 1.3.x (which has missing option
 *	passthrough so that <volume fstype="fuse" ...> won't work.
 *	Now use <volume fstype="encfs13" ...>
 *	Passthrough works in encfs 1.4.0 and up.
 *
 *	Released in the Public Domain.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/option.h>

static char *mt_opts;

/* This gets called as mount.encfs13 /srcdir /dstdir -o foo */
int main(int argc, const char **argv)
{
	unsigned int i = 0;
	const char **args;
	struct HXoption options_table[] = {
		{.sh = 'o', .type = HXTYPE_STRING, .ptr = &mt_opts,
		 .help = "Mount options"},
		HXOPT_AUTOHELP,
		HXOPT_TABLEEND,
	};
	if (HX_getopt(options_table, &argc, &argv, HXOPT_USAGEONERR) <= 0)
		return EXIT_FAILURE;
	if (argc < 2) {
		fprintf(stderr, "%s: You need to specify source directory and "
		        "mountpoint\n", *argv);
		return EXIT_FAILURE;
	}

	args = malloc(sizeof(char *) * 7);
	args[i++] = "encfs";
	args[i++] = argv[1]; /* src */
	args[i++] = argv[2]; /* mntpt */
	if (mt_opts != NULL) {
		args[i++] = "--";
		args[i++] = "-o";
		args[i++] = mt_opts;
	}
	args[i++] = NULL;
	assert(i < ARRAY_SIZE(args));
	execvp("encfs", const_cast2(char * const *, args));
	return -1;
}
