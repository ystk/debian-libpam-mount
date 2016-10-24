/*
 *	pam_mount
 *	Copyright Elvis Pfützenreuter <epx@conectiva.com>, 2000
 *	Copyright Jan Engelhardt, 2005 - 2010
 *	Copyright Bastian Kleineidam, 2005
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#define PAM_SM_ACCOUNT 1
#define PAM_SM_AUTH 1
#define PAM_SM_SESSION 1
#define PAM_SM_PASSWORD 1

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/proc.h>
#include <libHX.h>
#include "libcryptmount.h"
#include "pam_mount.h"

#ifndef PAM_EXTERN
#	define PAM_EXTERN
#endif

#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#	define CONFIGFILE "/etc/pam_mount.conf.xml"
#else
#	define CONFIGFILE "/etc/security/pam_mount.conf.xml"
#endif

struct pam_args {
	bool get_pw_from_pam, get_pw_interactive, propagate_pw;
};

/* Functions */
static void clean_config(pam_handle_t *, void *, int);
static int converse(pam_handle_t *, int, const struct pam_message **,
	struct pam_response **);
static int modify_pm_count(struct config *, char *, char *);
static void parse_pam_args(int, const char **);
static int read_password(pam_handle_t *, const char *, char **);

/* Variables */
static const char *envpath_saved;
struct config Config;
struct pam_args Args;

//-----------------------------------------------------------------------------
/**
 * parse_pam_args -
 * @argv:	NULL-terminated argument vector
 * @argc:	number of elements in @argc
 *
 * Global @Args is initialized, based on @argv.
 */
static void parse_pam_args(int argc, const char **argv)
{
	int i;

	assert(argc >= 0);
	for (i = 0; i < argc; i++)
		assert(argv[i] != NULL);

	/* first, set default values */
	Args.get_pw_from_pam    = true;
	Args.get_pw_interactive = true;
	Args.propagate_pw       = true;

	for (i = 0; i < argc; ++i) {
		if (strcasecmp("enable_pam_password", argv[i]) == 0)
			Args.get_pw_from_pam = true;
		else if (strcasecmp("disable_pam_password", argv[i]) == 0)
			Args.get_pw_from_pam = false;
		else if (strcasecmp("enable_interactive", argv[i]) == 0)
			Args.get_pw_interactive = true;
		else if (strcasecmp("disable_interactive", argv[i]) == 0)
			Args.get_pw_interactive = false;
		else if (strcasecmp("enable_propagate_password", argv[i]) == 0)
			Args.propagate_pw = true;
		else if (strcasecmp("disable_propagate_password", argv[i]) == 0)
			Args.propagate_pw = false;
		else if (strcasecmp("debug", argv[i]) == 0)
			Config.debug = 1;
		else
			w4rn("unknown pam_mount option \"%s\"\n", argv[i]);
	}
}

/**
 * clean_config -
 * @pamh:	PAM handle
 * @data:	custom data pointer
 * @err:
 *
 * Free data from a struct config variable.
 * Note: This is registered as a PAM callback function and is called directly.
 */
static void clean_config(pam_handle_t *pamh, void *data, int err)
{
	w4rn("Clean global config (%d)\n", err);
	freeconfig(data);
}

/**
 * clean_system_authtok -
 * @pamh:	PAM handle
 * @data:	custom data pointer
 * @err:
 *
 * Zero and free @data if it is not %NULL.
 * Note: This is registered as a PAM callback function and is called directly.
 *
 * FIXME: Not binary-password safe.
 */
static void clean_system_authtok(pam_handle_t *pamh, void *data, int errcode)
{
	w4rn("clean system authtok=%p (%d)\n", data, errcode);

	if (data != NULL) {
		unsigned int len = strlen(data) + 1;
		memset(data, 0, len);
		munlock(data, len);
		free(data);
	}
}

/**
 * converse -
 * @pamh:	PAM handle
 * @nargs:	number of messages
 * @message:	PAM message array
 * @resp:	user response array
 *
 * Note: Adapted from pam_unix/support.c.
 */
static int converse(pam_handle_t *pamh, int nargs,
    const struct pam_message **message, struct pam_response **resp)
{
	int retval;
	struct pam_conv *conv;

	assert(pamh != NULL);
	assert(nargs >= 0);
	assert(resp != NULL);

	*resp = NULL;
	retval = pam_get_item(pamh, PAM_CONV, static_cast(const void **,
	         static_cast(void *, &conv)));

	if (retval != PAM_SUCCESS) {
		l0g("pam_get_item: %s\n", pam_strerror(pamh, retval));
	} else if (conv == NULL || conv->conv == NULL) {
		w4rn("No converse function available\n");
	} else {
		retval = conv->conv(nargs, message, resp, conv->appdata_ptr);
		if (retval != PAM_SUCCESS)
			l0g("conv->conv(...): %s\n", pam_strerror(pamh, retval));
	}

	if (resp == NULL || *resp == NULL || (*resp)->resp == NULL)
		retval = PAM_AUTH_ERR;

	assert(retval != PAM_SUCCESS || (resp != NULL && *resp != NULL &&
	       (*resp)->resp != NULL));
	return retval; /* propagate error status */
}

/**
 * read_password -
 * @pamh:	PAM handle
 * @prompt:	a prompt message
 * @pass:	space for entered password
 *
 * Returns PAM error code or %PAM_SUCCESS.
 * Note: Adapted from pam_unix/support.c:_unix_read_password().
 */
static int read_password(pam_handle_t *pamh, const char *prompt, char **pass)
{
	int retval;
	struct pam_message msg;
	const struct pam_message *pmsg = &msg;
	struct pam_response *resp = NULL;

	assert(pamh != NULL);
	assert(pass != NULL);

	*pass = NULL;
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg       = (prompt == NULL) ? "Password: " : prompt;
	retval  = converse(pamh, 1, &pmsg, &resp);
	if (retval == PAM_SUCCESS)
		*pass = xstrdup(resp->resp);

	assert(retval != PAM_SUCCESS || (pass != NULL && *pass != NULL));
	return retval;
}

static void pmt_sigpipe_setup(bool block_it)
{
	static pthread_mutex_t sp_lock = PTHREAD_MUTEX_INITIALIZER;
	static int sp_blocked = 0;
	static bool sp_previous;
	sigset_t set, oldset;

	pthread_mutex_lock(&sp_lock);
	if (block_it) {
		if (++sp_blocked == 1) {
			sigemptyset(&set);
			sigaddset(&set, SIGPIPE);
			sigprocmask(SIG_BLOCK, &set, &oldset);
			sp_previous = sigismember(&oldset, SIGPIPE);
		}
	} else {
		if (--sp_blocked == 0 && sp_previous) {
			sigemptyset(&set);
			sigaddset(&set, SIGPIPE);
			sigtimedwait(&set, NULL, &(struct timespec){0, 0});
			sigprocmask(SIG_UNBLOCK, &set, NULL);
		}
	}

	pthread_mutex_unlock(&sp_lock);
}

static int common_init(pam_handle_t *pamh, int argc, const char **argv)
{
	const char *pam_user;
	char buf[8];
	int ret;

	ret = HX_init();
	if (ret <= 0)
		l0g("libHX init failed: %s\n", strerror(errno));
	ret = cryptmount_init();
	if (ret <= 0)
		l0g("libcryptmount init failed: %s\n", strerror(errno));

	initconfig(&Config);
	parse_pam_args(argc, argv);
	/*
	 * call pam_get_user again because ssh calls PAM fns from seperate
 	 * processes.
	 */
	ret = pam_get_user(pamh, &pam_user, NULL);
	if (ret != PAM_SUCCESS) {
		l0g("could not get user");
		/*
		 * do NOT return %PAM_SERVICE_ERR or root will not be able to
		 * su to other users.
		 * Also, if we could not get the user's info, an earlier auth
		 * module (like pam_unix2) likely blocked login already.
		 */
		return PAM_SUCCESS;
	}
	/*
	 * FIXME: free me! the dup is requried because result of pam_get_user()
	 * disappears (valgrind)
	 */
	Config.user = relookup_user(pam_user);
	if (!readconfig(CONFIGFILE, true, &Config))
		return PAM_SERVICE_ERR;

	/* reinitialize after @Debug may have changed */
	if (ehd_logctl(EHD_LOGFT_DEBUG, EHD_LOG_GET))
		ehd_logctl(EHD_LOGFT_DEBUG, EHD_LOG_UNSET);
	if (Config.debug)
		ehd_logctl(EHD_LOGFT_DEBUG, EHD_LOG_SET);

	snprintf(buf, sizeof(buf), "%u", Config.debug);
	setenv("_PMT_DEBUG_LEVEL", buf, true);

	pmt_sigpipe_setup(true);
	return -1;
}

static void common_exit(void)
{
	pmt_sigpipe_setup(false);
	cryptmount_exit();
	HX_exit();
}

static void auth_grab_authtok(pam_handle_t *pamh, struct config *config)
{
	char *authtok = NULL;
	int ret;

	if (Args.get_pw_from_pam) {
		char *ptr = NULL;

		ret = pam_get_item(pamh, PAM_AUTHTOK, static_cast(const void **,
		      static_cast(void *, &ptr)));
		if (ret == PAM_SUCCESS && ptr != NULL)
			authtok = xstrdup(ptr);
	}
	if (authtok == NULL && Args.get_pw_interactive) {
		ret = read_password(pamh, config->msg_authpw, &authtok);
		if (ret == PAM_SUCCESS && Args.propagate_pw) {
			/*
			 * pam_set_item() copies to PAM-internal memory.
			 *
			 * Using pam_set_item(PAM_AUTHTOK) here to make the
			 * password that was just entered available to further
			 * PAM modules.
			 */
			ret = pam_set_item(pamh, PAM_AUTHTOK, authtok);
			if (ret != PAM_SUCCESS)
				l0g("warning: failure to export password (%s)\n",
				    pam_strerror(pamh, ret));
		}
	}

	/*
	 * Save auth token for pam_mount itself, since PAM_AUTHTOK
	 * will be gone when the auth stage exits.
	 */
	if (authtok != NULL) {
		ret = pam_set_data(pamh, "pam_mount_system_authtok", authtok,
		                   clean_system_authtok);
		if (ret == PAM_SUCCESS) {
			if (mlock(authtok, strlen(authtok) + 1) < 0)
				w4rn("mlock authtok: %s\n", strerror(errno));
		} else {
			l0g("error trying to save authtok for session code\n");
		}
	}
}

/**
 * pam_sm_authenticate -
 * @pamh:	PAM handle
 * @flags:	PAM flags
 * @argc:	number of elements in @argv
 * @argv:	NULL-terminated argument vector
 *
 * Called by the PAM layer. The user's system password is added to PAM's
 * global module data. This is because pam_sm_open_session() does not allow
 * access to the user's password. Returns the PAM error code or %PAM_SUCCESS.
 */
PAM_EXTERN EXPORT_SYMBOL int pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	int ret = PAM_SUCCESS;

	assert(pamh != NULL);

	if ((ret = common_init(pamh, argc, argv)) != -1)
		return ret;
	w4rn(PACKAGE_STRING ": entering auth stage\n");
	auth_grab_authtok(pamh, &Config);
	common_exit();
	/*
	 * pam_mount is not really meant to be an auth module. So we should not
	 * hinder the login process.
	 */
	return PAM_SUCCESS;
}

/**
 * On login, $PATH is correctly set to ENV_ROOTPATH (from /etc/login.defs),
 * while on logout, it happens to be ENV_PATH only. This is problematic,
 * since some programs are in /sbin and /usr/sbin which is
 * often not contained in ENV_PATH.
 *
 * In short: Another workaround for coreutils.
 */
static void envpath_init(const char *new_path)
{
	envpath_saved = getenv("PATH");
	setenv("PATH", new_path, true);
}

static void envpath_restore(void)
{
	if (envpath_saved == NULL)
		unsetenv("PATH");
	else
		setenv("PATH", envpath_saved, true);
}

/**
 * modify_pm_count -
 * @config:
 * @user:
 * @operation:	string specifying numerical increment
 *
 * Calls out to the `pmvarrun` helper utility to adjust the mount reference
 * count in /var/run/pam_mount/@user for the specified user.
 * Returns the new reference count value on success, or -1 on error.
 *
 * Note: Modified version of pam_console.c:use_count()
 */
static int modify_pm_count(struct config *config, char *user,
    char *operation)
{
	FILE *fp = NULL;
	struct HXformat_map *vinfo;
	struct HXdeque *argv;
	struct HXproc proc;
	int ret = -1, use_count;

	assert(user != NULL);
	assert(operation != NULL);

	if ((vinfo = HXformat_init()) == NULL)
		goto out;
	format_add(vinfo, "USER", user);
	format_add(vinfo, "OPERATION", operation);
	misc_add_ntdom(vinfo, user);

	argv = arglist_build(config->command[CMD_PMVARRUN], vinfo);
	memset(&proc, 0, sizeof(proc));
	proc.p_flags = HXPROC_VERBOSE | HXPROC_STDOUT;
	proc.p_ops   = &pmt_dropprivs_ops;
	if ((ret = pmt_spawn_dq(argv, &proc)) <= 0) {
		l0g("error executing pmvarrun: %s\n", strerror(-ret));
		goto out;
	}
	ret = -1;
	if ((fp = fdopen(proc.p_stdout, "r")) == NULL)
		goto out2;
	if (fscanf(fp, "%d", &use_count) != 1)
		w4rn("error reading login count from pmvarrun\n");
	else
		w4rn("pmvarrun says login count is %d\n", use_count);
 out2:
	if (fp != NULL)
		fclose(fp);
	else
		close(proc.p_stdout);
	if (HXproc_wait(&proc) >= 0 && proc.p_exited && proc.p_status == 0)
		ret = use_count;
 out:
	if (vinfo != NULL)
		HXformat_free(vinfo);
	return ret;
}

/**
 * ses_grab_authtok - get the password from PAM
 *
 * Session stage: reretrieve password that the auth stage stored.
 * If that does not work, use interactive prompting if enabled.
 */
static char *ses_grab_authtok(pam_handle_t *pamh)
{
	char *authtok = NULL;
	int ret;

	ret = pam_get_data(pamh, "pam_mount_system_authtok",
	      static_cast(const void **, static_cast(void *, &authtok)));
	if (ret == PAM_SUCCESS)
		return authtok;

	/* No stored password, get one, if allowed to. */
	if (Args.get_pw_interactive) {
		ret = read_password(pamh, Config.msg_sessionpw, &authtok);
		if (ret != PAM_SUCCESS)
			/* authtok is %NULL now */
			l0g("warning: could not obtain password "
			    "interactively either\n");
	}
	if (authtok != NULL) {
		ret = pam_set_data(pamh, "pam_mount_system_authtok",
		      authtok, clean_system_authtok);
		if (ret == PAM_SUCCESS) {
			if (mlock(authtok, strlen(authtok) + 1) < 0)
				w4rn("mlock authtok: %s\n", strerror(errno));
		} else {
			l0g("error trying to save authtok for session code\n");
		}
	}
	/*
	 * Always proceed, even if there is no password. Some volumes may not
	 * need one, e.g. bind mounts and networked/unencrypted volumes.
	 */
	return authtok;
}

static int process_volumes(struct config *config, const char *authtok)
{
	int ret = PAM_SUCCESS;
	struct vol *vol;

	HXlist_for_each_entry(vol, &config->volume_list, list) {
		/*
		 * Remember what we processed already - the function can
		 * be called multiple times.
		 */
		if (vol->mnt_processed)
			continue;
		vol->mnt_processed = true;
		/*
		 * luserconf_volume_record_sane() is called here so that a user
		 * can nest loopback images. otherwise ownership tests will
		 * fail if parent loopback image not yet mounted.
		 * volume_record_sane() is here to be consistent.
		 */
		if (!volume_record_sane(config, vol))
			continue;
		if (!vol->globalconf &&
		    !luserconf_volume_record_sane(config, vol))
			continue;

		if (!mount_op(do_mount, config, vol, authtok)) {
			l0g("mount of %s failed\n", znul(vol->volume));
			ret = PAM_SERVICE_ERR;
		}
	}
	return ret;
}

static void assert_root(void)
{
	/*
	 * I know checking for 0 is rather unflexible, but it does - so far -
	 * account for all the bugreports involving insufficient permissions.
	 */
	if (geteuid() == 0)
		return;
	l0g("*** PAM_MOUNT WAS INVOKED WITH INSUFFICIENT PRIVILEGES. (euid=%ld)\n",
	    static_cast(long, geteuid()));
	l0g("*** THIS IS A BUG OF THE CALLER. CONSULT YOUR DISTRO.\n");
	l0g("*** Also see bugs.txt in the pam_mount source tarball/website documentation.\n");
}

/**
 * pam_sm_open_session -
 * @pamh:	PAM handle
 * @flags:	PAM flags
 * @argc:	number of elements in @argv
 * @argv:	NULL-terminated argument vector
 *
 * Entrypoint from the PAM layer. Starts the wheels and eventually mounts the
 * user's directories according to pam_mount.conf.xml. Returns the PAM error
 * code or %PAM_SUCCESS.
 */
PAM_EXTERN EXPORT_SYMBOL int pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	int ret;
	const char *krb5;
	char *system_authtok = NULL;
	const void *tmp;
	int getval;

	assert(pamh != NULL);

	if ((ret = common_init(pamh, argc, argv)) != -1)
		return ret;

	w4rn(PACKAGE_STRING ": entering session stage\n");

	/*
	 * Environment variables set with setenv() only last while PAM is
	 * active, i.e. disappear when the shell is started. On the other hand,
	 * variabled fed to pam_putenv() are only visible once the shell
	 * started.
	 */
	/*
	 * Get the Kerberos CCNAME so we can make it available to the
	 * mount command later on.
	 */
	krb5 = pam_getenv(pamh, "KRB5CCNAME");
	if (krb5 != NULL && setenv("KRB5CCNAME", krb5, true) < 0)
		l0g("KRB5CCNAME setenv failed\n");

	/* Store initialized config as PAM data */
	getval = pam_get_data(pamh, "pam_mount_config", &tmp);
	if (getval == PAM_NO_MODULE_DATA) {
		ret = pam_set_data(pamh, "pam_mount_config",
		      &Config, clean_config);
		if (ret != PAM_SUCCESS) {
			l0g("error trying to save config structure\n");
			goto out;
		}
		/* Up the reference count by one, for freeconfig */
		HX_init();
	}

	if (!expandconfig(&Config)) {
		l0g("error expanding configuration\n");
		ret = PAM_SERVICE_ERR;
		goto out;
	}
	if (Config.volume_list.items > 0)
		/* There are some volumes, so grab a password. */
		system_authtok = ses_grab_authtok(pamh);

	assert_root();
	envpath_init(Config.path);
	ret = process_volumes(&Config, system_authtok);

	/*
	 * Read luserconf after mounting of initial volumes. This makes it
	 * possible to store luserconfs on net volumes themselves.
	 */
	if (Config.luserconf != NULL && *Config.luserconf != '\0' &&
	    pmt_fileop_exists(Config.luserconf)) {
		w4rn("going to readconfig %s\n", Config.luserconf);
		if (!pmt_fileop_owns(Config.user, Config.luserconf)) {
			w4rn("%s does not exist or is not owned by user\n",
			     Config.luserconf);
		} else if (!readconfig(Config.luserconf, false, &Config)) {
			ret = PAM_SERVICE_ERR;
		} else if (!expandconfig(&Config)) {
			ret = PAM_SERVICE_ERR;
			l0g("error expanding configuration\n");
		}
	}

	if (Config.volume_list.items == 0) {
		w4rn("no volumes to mount\n");
		ret = PAM_SUCCESS;
	} else {
		/*
		 * If there are no global volumes, but luserconf volumes,
		 * and we still have no password, ask for one now.
		 */
		if (system_authtok == NULL)
			system_authtok = ses_grab_authtok(pamh);
		ret = process_volumes(&Config, system_authtok);
	}

	modify_pm_count(&Config, Config.user, "1");
	envpath_restore();
	if (getuid() == 0)
		/* Make sure root can always log in. */
		/* NB: I don't even wanna think of SELINUX's ambiguous UIDs... */
		ret = PAM_SUCCESS;

	/*
	 * If mounting something failed, e.g. ret = %PAM_SERVICE_ERR, we have
	 * to unravel everything and umount all volumes. But *only* if
	 * pam_mount was configured as a "required" module. How can this info
	 * be obtained?
	 * For now, always assume "optional", so that the volumes are
	 * definitely unmounted when the user logs out again.
	 */
	ret = PAM_SUCCESS;
 out:
	if (krb5 != NULL)
		unsetenv("KRB5CCNAME");
	w4rn("done opening session (ret=%d)\n", ret);
	common_exit();
	return ret;
}

/**
 * pam_sm_chauthtok -
 * @pamh:	PAM handle
 * @flags:	PAM flags
 * @argc:	number of elements in @argv
 * @argv:	NULL-terminated argument vector
 *
 * This is a placeholder function so PAM does not get mad.
 */
PAM_EXTERN EXPORT_SYMBOL int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

/**
 * pam_sm_close_session -
 * @pamh:	PAM handle
 * @flags:	PAM flags
 * @argc:	number of elements in @argv
 * @argv:	NULL-terminated argument vector
 *
 * Entrypoint from the PAM layer. Stops all wheels and eventually unmounts the
 * user's directories. Returns the PAM error code or %PAM_SUCCESS.
 *
 * FIXME: This function currently always returns %PAM_SUCCESS. Should it
 * return soemthing else when errors occur and all unmounts have been
 * attempted?
 */
PAM_EXTERN EXPORT_SYMBOL int pam_sm_close_session(pam_handle_t *pamh,
    int flags, int argc, const char **argv)
{
	const char *pam_user = NULL;
	int ret;

	assert(pamh != NULL);

	ret = HX_init();
	if (ret <= 0)
		l0g("libHX init failed: %s\n", strerror(errno));
	ret = PAM_SUCCESS;
	w4rn("received order to close things\n");
	assert_root();
	if (Config.volume_list.items == 0) {
		w4rn("No volumes to umount\n");
		goto out;
	}

	/*
	 * call pam_get_user() again because ssh calls PAM fns from seperate
 	 * processes.
	 */
	ret = pam_get_user(pamh, &pam_user, NULL);
	if (ret != PAM_SUCCESS) {
		l0g("could not get user\n");
		goto out;
	}
	/*
	 * FIXME: free me! the dup is requried because result of pam_get_user
	 * disappears (valgrind)
	 */
	Config.user = relookup_user(pam_user);
	/* if our CWD is in the home directory, it might not get umounted */
	if (chdir("/") != 0)
		l0g("could not chdir\n");

 out:
	envpath_init(Config.path);
	if (modify_pm_count(&Config, Config.user, "-1") > 0)
		w4rn("%s seems to have other remaining open sessions\n",
		     Config.user);
	else
		umount_final(&Config);

	envpath_restore();
	/*
	 * Note that PMConfig is automatically freed later in clean_config()
	 */
	w4rn("pam_mount execution complete\n");
	HX_exit();
	return ret;
}

/**
 * pam_sm_setcred -
 * @pamh:	PAM handle
 * @flags:	PAM flags
 * @argc:	number of elements in @argv
 * @argv:	NULL-terminated argument vector
 *
 * This is a placeholder function so PAM does not get mad.
 */
PAM_EXTERN EXPORT_SYMBOL int pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	return PAM_SUCCESS;
}

/**
 * pam_sm_acct_mgmt -
 * @pamh:	PAM handle
 * @flags:	PAM flags
 * @argc:	number of elements in @argv
 * @argv:	NULL-terminated argument vector
 *
 * This is a placeholder function so PAM does not get mad.
 */
PAM_EXTERN EXPORT_SYMBOL int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	return PAM_IGNORE;
}

#ifdef PAM_STATIC
/* static module data */

EXPORT_SYMBOL struct pam_module _pam_mount_modstruct = {
	.name                 = "pam_mount",
	.pam_sm_authenticate  = pam_sm_authenticate,
	.pam_sm_setcred       = pam_sm_setcred,
	.pam_sm_acct_mgmt     = pam_sm_acct_mgmt,
	.pam_sm_open_sesion   = pam_sm_open_session,
	.pam_sm_close_session = pam_sm_close_session,
	.pam_sm_chauthtok     = pam_sm_chauthtok,
};

#endif
