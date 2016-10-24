/*
 *	pam_mount
 *	Copyright W. Michael Petullo <mike@flyn.org>, 2004
 *	Copyright Jan Engelhardt, 2005-2011
 *	Copyright Bastian Kleineidam <calvin [at] debian org>, 2005
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
/*
pmvarrun.c -- Updates /run/pam_mount/<user>.
    A seperate program is needed so that /run/pam_mount/<user> may be
    created with a pam_mount-specific security context (otherwise SELinux
    policy will conflict with whatever called pam_mount.so).
*/

#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/io.h>
#include <libHX/string.h>
#include <pwd.h>
#include "libcryptmount.h"
#include "pam_mount.h"

/* Definitions */
#define ASCIIZ_LLX      sizeof("0xFFFFFFFF""FFFFFFFF")
#define VAR_RUN_PMT     RUNDIR "/pam_mount"

struct settings {
	char *user;
	long operation;
};

/* Functions */
static int create_var_run(void);
static int modify_pm_count(const char *, long);
static int open_and_lock(const char *, long);
static void parse_args(const int, const char **, struct settings *);
static long read_current_count(int, const char *);
static void set_defaults(struct settings *);
static void usage(int, const char *);
static int write_count(int, long, const char *);

static unsigned int pmvr_debug;

/**
 * usage - display help
 * @exitcode:	numeric value we will be exiting with
 * @error:	descriptive error string
 *
 * Displays the help string and an optional extra error message.
 */
static void usage(const int exitcode, const char *error)
{
	fprintf(stderr, "Usage: pmvarrun -u USER [-o NUMBER] [-d]\n");
	if (error != NULL)
		fprintf(stderr, "%s\n\n", error);
	exit(exitcode);
}

/**
 * set_defaults -
 * @settings:	pointer to settings structure
 */
static void set_defaults(struct settings *settings)
{
	const char *s;

	settings->user      = NULL;
	settings->operation = 1;

	if ((s = getenv("_PMT_DEBUG_LEVEL")) != NULL &&
	    strtoul(s, NULL, 0) != 0) {
		if (!pmvr_debug)
			ehd_logctl(EHD_LOGFT_DEBUG, EHD_LOG_SET);
		pmvr_debug = true;
	}
}

/*
 * from git://dev.medozas.de/vitalnix /src/libvxutil/util.c
 */
static bool valid_username(const char *n)
{
	if (*n == '\0')
		return false;

	/*
	 * Note to future editors: Some systems disallow leading digits for
	 * usernames. Possibly because it is concerned about badly-written
	 * programs detecting numeric UIDs by merely doing
	 * strtoul(s, &e, 0) && s != e, which falls victim to usernames
	 * with leading digits.
	 * So pam_mount, in its original form at least (distros can patch
	 * their copy up as they see fit), should at best reject
	 * leading digits too.
	 */
	/*
	 * Cannot use isalpha/isdigit here since that may include
	 * more characters.
	 */
	if (!((*n >= 'A' && *n <= 'Z') || (*n >= 'a' && *n <= 'z') ||
	    *n == '_'))
		return false;

	while (*n != '\0') {
		bool valid;

		if (*n == '$' && *(n+1) == '\0') /* Samba accounts */
			return true;

		valid = (*n >= 'A' && *n <= 'Z') || (*n >= 'a' && *n <= 'z') ||
		        (*n >= '0' && *n <= '9') || *n == '_' || *n == '.' ||
		        *n == '-' || *n == ' ' || *n == '\\';
		if (!valid)
			return false;
		++n;
	}

	return true;
}

/**
 * str_to_long -
 * @n:	string to analyze
 *
 * Calls @strtol on @n using base 10 and makes sure there were no invalid
 * characters in @n. Returns the value, or %LONG_MAX in case of an
 * over-/underflow.
 * NOTE: This function is only referenced from pmvarrun.c.
 */
long str_to_long(const char *n)
{
	long val;
	char *endptr = NULL;
	if (n == NULL) {
		l0g("count string is NULL\n");
		return LONG_MAX;
	}
	val = strtol(n, &endptr, 10);
	if (*endptr != '\0') {
		l0g("count string is not valid\n");
		return LONG_MAX;
	}
	return val;
}

/**
 * parse_args -
 * @argc:	number of elements in @argv
 * @argv:	NULL-terminated argument vector
 * @settings:	pointer to settings structure
 *
 * Parse options from @argv and put it into @settings.
 */
static void parse_args(int argc, const char **argv, struct settings *settings)
{
	int c;

	while ((c = getopt(argc, const_cast2(char * const *, argv),
	    "hdo:u:")) >= 0) {
		switch (c) {
		case 'h':
			usage(EXIT_SUCCESS, NULL);
			break;
		case 'd':
			if (!pmvr_debug)
				ehd_logctl(EHD_LOGFT_DEBUG, EHD_LOG_SET);
			pmvr_debug = true;
			break;
		case 'o':
			settings->operation = str_to_long(optarg);
			if (settings->operation == LONG_MAX ||
			    settings->operation == LONG_MIN)
				usage(EXIT_FAILURE, "count string is not valid");
			break;
		case 'u':
			if (!valid_username(optarg)) {
				fprintf(stderr, "Invalid user name\n");
				exit(EXIT_FAILURE);
			}
			if ((settings->user = HX_strdup(optarg)) == NULL)
				perror("malloc");
			break;
		default:
			usage(EXIT_FAILURE, NULL);
			break;
		}
	}
}

/**
 * modify_pm_count -
 * @user:	user to poke on
 * @amount:	increment (usually -1, 0 or +1)
 *
 * Adjusts /var/run/pam_mount/@user by @amount, or deletes the file if the
 * resulting value (current + @amount) is <= 0. Returns >= 0 on success to
 * indicate the new login count, or negative to indicate errno. -ESTALE and
 * -EOVERFLOW are passed up from subfunctions and must be handled in the
 * caller.
 */
static int modify_pm_count(const char *user, long amount)
{
	char filename[PATH_MAX + 1];
	struct passwd *pent;
	struct stat sb;
	int fd, ret;
	long val;

	assert(user != NULL);

	if ((pent = getpwnam(user)) == NULL) {
		ret = -errno;
		l0g("could not resolve user %s\n", user);
		return ret;
	}

	if (stat(VAR_RUN_PMT, &sb) < 0) {
		if (errno != ENOENT) {
			ret = -errno;
			l0g("unable to stat " VAR_RUN_PMT ": %s\n",
			    strerror(errno));
			return ret;
		}
		if ((ret = create_var_run()) < 0)
			return ret;
	}

	snprintf(filename, sizeof(filename), VAR_RUN_PMT "/%s", user);
	while ((ret = fd = open_and_lock(filename, pent->pw_uid)) == -EAGAIN)
		/* noop */;
	if (ret < 0)
		return ret;

	if ((val = read_current_count(fd, filename)) < 0) {
		close(fd);
		return val;
	}

	w4rn("parsed count value %ld\n", val);
	/* amount == 0 implies query */
	ret = 1;
	if (amount != 0)
		ret = write_count(fd, val + amount, filename);

	close(fd);
	return (ret < 0) ? ret : val + amount;
}

int main(int argc, const char **argv)
{
	struct settings settings;
	int ret;

	ehd_logctl(EHD_LOGFT_NOSYSLOG, EHD_LOG_SET);
	set_defaults(&settings);
	parse_args(argc, argv, &settings);

	if (settings.user == NULL)
		usage(EXIT_FAILURE, NULL);

	ret = modify_pm_count(settings.user, settings.operation);
	if (ret == -ESTALE) {
		printf("0\n");
		return EXIT_SUCCESS;
	} else if (ret < 0) {
		return EXIT_FAILURE;
	}

	/* print current count so pam_mount module may read it */
	printf("%d\n", ret);
	return EXIT_SUCCESS;
}

//-----------------------------------------------------------------------------
/**
 * create_var_run -
 *
 * Creates the /run/pam_mount directory required by pmvarrun and sets
 * proper permissions on it.
 *
 * Returns >0 for success or <=0 to indicate errno.
 */
static int create_var_run(void)
{
	static const unsigned int mode = S_IRUGO | S_IXUGO | S_IWUSR;
	int ret;

	w4rn("creating " VAR_RUN_PMT);
	if (HX_mkdir(VAR_RUN_PMT, mode) < 0) {
		ret = -errno;
		l0g("unable to create " VAR_RUN_PMT ": %s\n", strerror(errno));
		return ret;
	}
	if (chown(VAR_RUN_PMT, 0, 0) < 0) {
		ret = -errno;
		l0g("unable to chown " VAR_RUN_PMT ": %s\n", strerror(errno));
		return ret;
	}

	/*
	 * 0755: `su` creates file group owned by user and then releases root
	 * permissions. User needs to be able to access file on logout.
	 */
	if (chmod(VAR_RUN_PMT, mode) < 0) {
		ret = -errno;
		l0g("unable to chmod " VAR_RUN_PMT ": %s\n", strerror(errno));
		return ret;
	}

	return 1;
}

/**
 * open_and_lock -
 * @filename:	file to open
 *
 * Creates if necessary, opens and chown()s @filename, and locks it.
 * Returns the fd if all of that succeeded, -EAGAIN if the file was unlinked
 * during operation (see below), -ESTALE if the lock could not be obtained,
 * and <0 otherwise to indicate errno.
 */
static int open_and_lock(const char *filename, long uid) {
	struct flock lockinfo = {
		.l_type   = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start  = 0,
		.l_len	= 0,
	};
	struct stat sb;
	int fd, ret;

	if ((fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR)) < 0) {
		ret = -errno;
		l0g("unable to open %s: %s\n", filename, strerror(errno));
		return ret;
	}
	if (fchown(fd, uid, 0) < 0) {
		ret = -errno;
		l0g("unable to chown %s: %s\n", filename, strerror(errno));
		return ret;
	}

	/*
	 * Note: Waiting too long might interfere with LOGIN_TIMEOUT from
	 * /etc/login.defs, and /bin/login itself may prematurely kill the
	 * /session.
	 */
	alarm(20);
	ret = fcntl(fd, F_SETLKW, &lockinfo);
	alarm(0);
	if (ret == EAGAIN) {
		/*
		 * [Flyn] If someone has locked the file and not written to it
		 * in at least 20 seconds, we assume they either forgot to
		 * unlock it or are catatonic -- chances are slim that they are
		 * in the middle of a read-write cycle and I do not want to
		 * make us lock users out. Perhaps I should just return
		 * %PAM_SUCCESS instead and log the event? Kill the process
		 * holding the lock? Options abound... For now, we ignore it.
		 *
		 * [CCJ] pmvarrun is the only one ever writing to that file,
		 * and we keep the lock as short as possible. So if there is no
		 * response within the time limit, something is fouled up (e.g. 
		 * NFS server not responding -- though /var/run should at best
		 * not be on an NFS mount).  Continue, let user log in, do not
		 * change anything.
		 */
		w4rn("stale lock on file %s - continuing without increasing"
		     "pam_mount reference count\n", filename);
		close(fd);
		return -ESTALE;
	}

	/*
	 * It is possible at this point that the file has been removed by a
	 * previous login; if this happens, we need to start over.
	 */
	if (stat(filename, &sb) < 0) {
		ret = -errno;
		close(fd);
		if (ret == -ENOENT)
			return -EAGAIN;
		return ret;
	}

	return fd;
}

/**
 * read_current_count -
 * @fd:	file descriptor to read from
 *
 * Reads the current user's reference count from @fd and returns the value
 * on success. Otherwise, returns -EOVERFLOW in case we suspect a problem or
 * <0 to indicate errno.
 */
static long read_current_count(int fd, const char *filename) {
	char buf[ASCIIZ_LLX] = {};
	long ret;

	if ((ret = read(fd, buf, sizeof(buf))) < 0) {
		ret = -errno;
		l0g("read error on %s: %s\n", filename, strerror(errno));
		close(fd);
		return ret;
	} else if (ret == 0) {
		/* File is empty, ret is already 0 -- we are set. */
	} else if (ret < sizeof(buf)) {
		char *p;
		if ((ret = strtol(buf, &p, 0)) >= LONG_MAX || p == buf) {
			l0g("parse problem / session count corrupt "
			    "(overflow), check your refcount file\n");
			return -EOVERFLOW;
		}
	} else if (ret >= sizeof(buf)) {
		l0g("session count corrupt (overflow)\n");
		return -EOVERFLOW;
	}

	return ret;
}

/**
 * write_count -
 * @fd:		file descriptor to write to
 * @nv:		new value to write
 * @filename:	filename, only used for l0g()
 *
 * Writes @nv as a number in hexadecimal to the start of the file @fd and
 * truncates the file to the written length.
 */
static int write_count(int fd, long nv, const char *filename) {
	char buf[ASCIIZ_LLX];
	int wrt, len, ret;

	if (nv <= 0) {
		if (unlink(filename) >= 0)
			return true;
		if (errno != EPERM)
			l0g("could not unlink %s: %s\n", filename, strerror(errno));
		/*
		 * Fallback to just blanking the file. This can happen when
		 * pmvarrun is called as unprivileged user.
		 */
		if (ftruncate(fd, 0) < 0)
			w4rn("truncate failed: %s\n", strerror(errno));
		return true;
	}

	if ((ret = lseek(fd, 0, SEEK_SET)) != 0) {
		ret = -errno;
		l0g("failed to seek in %s: %s\n", filename, strerror(errno));
		return ret;
	}

	len = snprintf(buf, sizeof(buf), "0x%lX", nv);
	if ((wrt = write(fd, buf, len)) != len) {
		ret = -errno;
		l0g("wrote %d of %d bytes; write error on %s: %s\n",
		    (wrt < 0) ? 0 : wrt, len, filename, strerror(errno));
		return ret;
	}

	if (ftruncate(fd, len) < 0) {
		ret = -errno;
		l0g("truncate failed: %s\n", strerror(errno));
		return ret;
	}

	return 1;
}
