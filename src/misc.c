/*
 *	Copyright (C) Elvis Pfützenreuter, 2000
 *	Copyright © Jan Engelhardt, 2005 - 2008
 *	Copyright © Bastian Kleineidam, 2005
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/deque.h>
#include <libHX/list.h>
#include <libHX/string.h>
#include <pwd.h>
#include "pam_mount.h"

struct HXbtree;

/**
 * misc_dump_id - print user IDs
 */
void misc_dump_id(const char *where)
{
	w4rn("%s: (ruid/rgid=%u/%u, e=%u/%u)\n", where,
	     static_cast(unsigned int, getuid()),
	     static_cast(unsigned int, getgid()),
	     static_cast(unsigned int, geteuid()),
	     static_cast(unsigned int, getegid()));
}

/**
 * pmt_fileop_exists -
 * @file:	file to check
 *
 * Check if a file exists (if it can be stat()'ed) and return positive
 * non-zero if that was successful. Returns 0 for error. %errno will be set
 * in case of error.
 */
int pmt_fileop_exists(const char *file)
{
	struct stat sb;
	assert(file != NULL);
	return stat(file, &sb) == 0;
}


/**
 * pmt_fileop_owns -
 * @user:	user to check for
 * @file:	file to check
 *
 * Checks whether @user owns @file. Returns positive non-zero if this is the
 * case, otherwise zero. If an error occurred, zero is returned and %errno
 * is set. (For the success case, %errno is undefined.)
 */
int pmt_fileop_owns(const char *user, const char *file)
{
	struct stat filestat;
	struct passwd *userinfo;

	assert(user != NULL);
	assert(file != NULL);

	if ((userinfo = getpwnam(user)) == NULL) {
		l0g("user %s could not be translated to UID\n",
		    user);
		return 0;
	}

	if (stat(file, &filestat) != 0) {
		w4rn("file %s could not be stat'ed\n", file);
		return 0;
	}

	return filestat.st_uid == userinfo->pw_uid &&
	       !S_ISLNK(filestat.st_mode);
}

/**
 * arglist_log - dump command
 * @argq:	argument list
 *
 * Log @argq using misc_warn() when debugging is turned on.
 */
void arglist_log(const struct HXdeque *argq)
{
	const struct HXdeque_node *n;
	hxmc_t *str = NULL;

	if (!pmtlog_path[PMTLOG_DBG][PMTLOG_STDERR] &&
	    !pmtlog_path[PMTLOG_DBG][PMTLOG_SYSLOG])
		return;

	str = HXmc_meminit(NULL, 80);
	for (n = argq->first; n != NULL; n = n->next) {
		HXmc_strcat(&str, "'");
		HXmc_strcat(&str, n->ptr);
		HXmc_strcat(&str, "' ");
	}

	misc_warn("command: %s\n", str);
	HXmc_free(str);
}

void arglist_llog(const char *const *argv)
{
	hxmc_t *str = NULL;

	if (!Debug)
		return;

	str = HXmc_meminit(NULL, 80);
	while (*argv != NULL) {
		HXmc_strcat(&str, "'");
		HXmc_strcat(&str, *argv);
		HXmc_strcat(&str, "' ");
		++argv;
	}

	misc_warn("command: %s\n", str);
	HXmc_free(str);
}

/**
 * arglist_add -
 * @argq:	argument list to add to
 * @arg:	raw argument
 * @vinfo:	substitution map
 *
 * Expands @arg according to @vinfo and adds it to the @argq list.
 */
void arglist_add(struct HXdeque *argq, const char *arg,
    const struct HXformat_map *vinfo)
{
	char *filled;

	if (HXformat2_aprintf(vinfo, &filled, arg) == 0)
		/*
		 * This case may happen with e.g. %(before="-o" OPTIONS) where
		 * OPTIONS is empty. And options expanding to nothing are
		 * certainly valid.
		 */
		return;

	if (filled == NULL || HXdeque_push(argq, filled) == NULL)
		misc_log("malloc: %s\n", strerror(errno));
}

/**
 * arglist_build - build argument list
 * @cmd:	raw unsubstituted command
 * @vinfo:	substitution map
 *
 * Substitutes %() placeholders in the commands (@cmd) with values from @vinfo
 * and returns the result, suitable for spawn_qstart().
 */
struct HXdeque *arglist_build(const struct HXdeque *cmd,
    const struct HXformat_map *vinfo)
{
	const struct HXdeque_node *n;
	struct HXdeque *aq;

	if ((aq = HXdeque_init()) == NULL)
		misc_log("malloc: %s\n", strerror(errno));

	for (n = cmd->first; n != NULL; n = n->next)
		arglist_add(aq, n->ptr, vinfo);

	arglist_log(aq);
	return aq;
}

/**
 * relookup_user -
 * @user:	The user to retrieve
 *
 * Relookup the user. This is done to account for case-insensitivity of
 * usernames with LDAP. Returns a copy of the real username (as stored in
 * the user database).
 */
char *relookup_user(const char *user)
{
	struct passwd *pe;
	if ((pe = getpwnam(user)) == NULL)
		return xstrdup(user);
	else
		return xstrdup(pe->pw_name);
}

/**
 * misc_add_ntdom -
 * @v:		substitution data
 * @user:	username to add
 *
 * Splits up @user into domain and user parts (if applicable) and adds
 * %(DOMAIN_NAME) and %(DOMAIN_USER) to @v. If @user is not of the form
 * "domain\user", %(DOMAIN_NAME) will be added as an empty tag, and
 * %(DOMAIN_USER) will be the same as @v. It is assumed that @user is also
 * part of @v, and hence, will not go out of scope as long as %(DOMAIN_*) is
 * in @v.
 */
void misc_add_ntdom(struct HXformat_map *v, const char *user)
{
	char *ptr, *tmp;

	if ((ptr = strchr(user, '\\')) == NULL) {
		format_add(v, "DOMAIN_NAME", NULL);
		format_add(v, "DOMAIN_USER", user);
		return;
	}

	if ((tmp = HX_strdup(user)) == NULL) {
		perror("HX_strdup");
		return;
	}
	ptr = strchr(tmp, '\\');
	assert(ptr != NULL);
	*ptr++ = '\0';

	format_add(v, "DOMAIN_NAME", tmp);
	format_add(v, "DOMAIN_USER", ptr);
	free(tmp);
}

bool kvplist_contains(const struct HXclist_head *head, const char *key)
{
	const struct kvp *kvp;

	HXlist_for_each_entry(kvp, head, list)
		if (strcmp(kvp->key, key) == 0)
			return true;
	return false;
}

char *kvplist_get(const struct HXclist_head *head, const char *key)
{
	const struct kvp *kvp;

	HXlist_for_each_entry(kvp, head, list)
		if (strcmp(kvp->key, key) == 0)
			return kvp->value;
	return NULL;
}

void kvplist_genocide(struct HXclist_head *head)
{
	struct kvp *kvp, *next;

	HXlist_for_each_entry_safe(kvp, next, head, list) {
		free(kvp->key);
		free(kvp->value);
		free(kvp);
	}
}

/**
 * kvplist_to_str -
 * @optlist:	option list
 *
 * Transform the option list into a flat string. Allocates and returns the
 * string. Caller has to free it. Used for debugging.
 */
hxmc_t *kvplist_to_str(const struct HXclist_head *optlist)
{
	const struct kvp *kvp;
	hxmc_t *ret = HXmc_meminit(NULL, 0);

	if (optlist == NULL)
		return ret;

	HXlist_for_each_entry(kvp, optlist, list) {
		HXmc_strcat(&ret, kvp->key);
		if (kvp->value != NULL && *kvp->value != '\0') {
			HXmc_strcat(&ret, "=");
			HXmc_strcat(&ret, kvp->value);
		}
		HXmc_strcat(&ret, ",");
	}

	if (*ret != '\0')
		/*
		 * When string is not empty, there is always at least one
		 * comma -- nuke it.
		 */
		ret[HXmc_length(ret)-1] = '\0';

	return ret;
}

/**
 * xmalloc - allocate memory
 * @n:	size of the new buffer
 *
 * Wrapper around malloc() that warns when no new memory block could be
 * obtained.
 */
void *xmalloc(size_t n)
{
	void *ret;
	if ((ret = malloc(n)) == NULL)
		l0g("%s: Could not allocate %lu bytes\n",
		    __func__, static_cast(unsigned long, n));
	return ret;
}

/**
 * xrealloc - resize memory block
 * @orig:	original address of the buffer
 * @n:		new size of the buffer
 *
 * Wrapper around realloc() that warns when no new memory block could be
 * obtained.
 */
void *xrealloc(void *orig, size_t n)
{
	void *ret;
	if ((ret = realloc(orig, n)) == NULL)
		l0g("%s: Could not reallocate to %lu bytes\n",
		    __func__, static_cast(unsigned long, n));
	return ret;
}

/**
 * xstrdup -
 * @src:	source string
 *
 * Basically just the usual strdup(), but with error reporting to fprintf()
 * should allocation fail.
 */
char *xstrdup(const char *src)
{
	char *ret = HX_strdup(src);
	if (ret == NULL)
		l0g("%s: Could not allocate %lu bytes\n",
		    __func__, strlen(src));
	return ret;
}
