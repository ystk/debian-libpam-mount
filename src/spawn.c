/*
 *	Copyright © Jan Engelhardt, 2006 - 2008
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/deque.h>
#include <libHX/proc.h>
#include <libHX/string.h>
#include <grp.h>
#include <pwd.h>
#include "pam_mount.h"

static pthread_mutex_t pmt_sigchld_lock = PTHREAD_MUTEX_INITIALIZER;
static int pmt_sigchld_cleared = 0;
static struct sigaction pmt_sigchld_old;

/**
 * spawn_set_sigchld -
 *
 * Save the old SIGCHLD handler and then set SIGCHLD to SIG_DFL. This is used
 * against GDM which does not reap childs as we wanted in its SIGCHLD handler,
 * so we install our own handler. Returns the value from sigaction().
 */
static void spawn_set_sigchld(void *data)
{
	static struct sigaction nh = {
		.sa_handler = SIG_DFL,
	};

	pthread_mutex_lock(&pmt_sigchld_lock);
	if (++pmt_sigchld_cleared == 1)
		sigaction(SIGCHLD, &nh, &pmt_sigchld_old);
	pthread_mutex_unlock(&pmt_sigchld_lock);
}

/**
 * spawn_restore_sigchld -
 *
 * Restore the SIGCHLD handler that was saved during spawn_set_sigchld().
 * Returns the value from sigaction().
 */
static void spawn_restore_sigchld(void *data)
{
	pthread_mutex_lock(&pmt_sigchld_lock);
	if (--pmt_sigchld_cleared == 0)
		sigaction(SIGCHLD, &pmt_sigchld_old, NULL);
	pthread_mutex_unlock(&pmt_sigchld_lock);
}

int pmt_spawn_dq(struct HXdeque *argq, struct HXproc *proc)
{
	char **argv = reinterpret_cast(char **, HXdeque_to_vec(argq, NULL));
	const struct HXdeque_node *n;
	bool ret;

	ret = HXproc_run_async(const_cast2(const char * const *, argv), proc);
	free(argv);
	for (n = argq->first; n != NULL; n = n->next)
		HXmc_free(n->ptr);
	HXdeque_free(argq);
	return ret;
}

/**
 * set_myuid -
 * @user:	switch to specified user
 *
 * set_myuid() is called in the child process as a result of the 
 * spawn_start() fork, before exec() will take place.
 *
 * If @users is %NULL, the UID is changed to root. (In most cases, we are
 * already root, though.)
 *
 * If @user is not %NULL, the UID of the current process is changed to that of
 * @user. Also, as a bonus for FUSE daemons, we set the HOME and USER
 * environment variables. setsid() is called so that FUSE daemons (e.g. sshfs)
 * get a new session identifier and do not get killed by the login program
 * after PAM authentication is successful.
 *
 * chdir("/") is called so that fusermount does not get stuck in a
 * non-readable directory (by means of doing `su - unprivilegeduser`)
 */
static void set_myuid(void *data)
{
	const char *user = data;

	setsid();
	if (chdir("/") < 0)
		;
	if (user == NULL) {
		misc_dump_id("set_myuid<pre>");
		if (setuid(0) < 0) {
			l0g("error setting uid to 0\n");
			return;
		}
	} else {
		/* Set UID and GID to the user's one */
		const struct passwd *real_user;
		w4rn("setting uid to user %s\n", user);
		if ((real_user = getpwnam(user)) == NULL) {
			l0g("could not get passwd entry for user %s\n", user);
			return;
		}
#ifdef HAVE_INITGROUPS
		initgroups(real_user->pw_name, real_user->pw_gid);
#endif
		if (setgid(real_user->pw_gid) == -1) {
			l0g("could not set gid to %ld\n",
			    static_cast(long, real_user->pw_gid));
			return;
		}
		if (setuid(real_user->pw_uid) == -1) {
			l0g("could not set uid to %ld\n",
			    static_cast(long, real_user->pw_uid));
			return;
		}
		setenv("HOME", real_user->pw_dir, 1);
		setenv("USER", real_user->pw_name, 1);
	}
	misc_dump_id("set_myuid<post>");
}

const struct HXproc_ops pmt_dropprivs_ops = {
	.p_prefork  = spawn_set_sigchld,
	.p_postfork = set_myuid,
	.p_complete = spawn_restore_sigchld,
};

const struct HXproc_ops pmt_spawn_ops = {
	.p_prefork  = spawn_set_sigchld,
	/* no postfork */
	.p_complete = spawn_restore_sigchld,
};
