/*
 *	Copyright Elvis Pfützenreuter, 2000
 *	Copyright Jan Engelhardt, 2006 - 2009
 *	Copyright Bastian Kleineidam, 2005
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <config.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libHX/ctype_helper.h>
#include <libHX/defs.h>
#include <libHX/deque.h>
#include <libHX/io.h>
#include <libHX/proc.h>
#include <libmount.h>
#include <grp.h>
#include <pwd.h>
#include "libcryptmount.h"
#include "pam_mount.h"

/* Functions */
static inline bool mkmountpoint(struct vol *, const char *);

//-----------------------------------------------------------------------------
/**
 * log_output
 * @fd:		file descriptor to read from
 * @cmsg:	conditional message
 *
 * Reads all data from @fd and logs it using w4rn(). @fd is usually connected
 * to a pipe to another process's stdout or stderr. Only if @fd actually has
 * output for us, @cmsg will be printed.
 *
 * @fd will be closed.
 */
static void log_output(int fd, const char *cmsg)
{
	hxmc_t *buf = NULL;
	FILE *fp;

	if ((fp = fdopen(fd, "r")) == NULL) {
		w4rn("error opening file: %s\n", strerror(errno));
		close(fd);
		return;
	}

	setvbuf(fp, NULL, _IOLBF, 0);
	do {
		if (HX_getl(&buf, fp) == NULL)
			break;
		HX_chomp(buf);
		if (*buf != '\0' && cmsg != NULL) {
			l0g("%s", cmsg);
			cmsg = NULL;
		}

		l0g("%s\n", buf);
	} while (true);
	fclose(fp);
	HXmc_free(buf);
}

/**
 * run_ofl -
 * @config:	current configuration
 * @vinfo:
 *
 * Runs `ofl` on a directory/mountpoint and logs its output, for debugging
 * purposes. (ofl is a better-suited lsof/fuser.)
 */
static void run_ofl(const struct config *const config, const char *mntpt,
    unsigned int signum)
{
	struct HXformat_map *vinfo;
	struct HXproc proc;
	struct HXdeque *argv;
	struct stat sb;
	int ret;

	if (stat(mntpt, &sb) < 0 && errno == ENOENT)
		return;

	vinfo = HXformat_init();
	if (vinfo == NULL)
		return;
	format_add(vinfo, "MNTPT", mntpt);
	HXformat_add(vinfo, "SIGNAL", reinterpret_cast(void *,
		static_cast(long, signum)), HXFORMAT_IMMED | HXTYPE_UINT);
	argv = arglist_build(config->command[CMD_OFL], vinfo);
	HXformat_free(vinfo);
	if (argv == NULL)
		return;
	memset(&proc, 0, sizeof(proc));
	proc.p_flags = HXPROC_VERBOSE;
	ret = pmt_spawn_dq(argv, &proc);
	if (ret <= 0)
		l0g("error executing ofl: %s\n", strerror(-ret));
	else
		HXproc_wait(&proc);
}

/**
 * Compares a given utab entry to the volume. crypt-type volumes will always
 * be compared case-sensitive since they always use an existing file.
 */
static bool pmt_utabent_matches(const struct vol *vpt, struct libmnt_fs *fs)
{
	int (*xcmp)(const char *, const char *);
	const char *source = mnt_fs_get_source(fs);
	const char *target = mnt_fs_get_target(fs);
	bool result = false;

	xcmp = fstype2_icase(vpt->type) ? strcasecmp : strcmp;
	if (source != NULL)
		result = xcmp(vpt->volume, source) == 0;
	if (target != NULL)
		result &= strcmp(vpt->mountpoint, target) == 0;
	return result;
}

/**
 * already_mounted -
 * @config:	current config
 * @vpt:	volume descriptor
 * @vinfo:
 *
 * Checks if @config->volume[@vol] is already mounted, and returns 1 if this
 * the case, 0 if not and -1 on error.
 */
int pmt_already_mounted(const struct config *const config,
    const struct vol *vpt, struct HXformat_map *vinfo)
{
	struct libmnt_context *ctx;
	struct libmnt_table *table;
	struct libmnt_iter *iter;
	struct libmnt_fs *fs;
	int ret = 0;

	ctx = mnt_new_context();
	if (ctx == NULL)
		return -1;
	if (mnt_context_get_mtab(ctx, &table) != 0)
		goto out;
	iter = mnt_new_iter(MNT_ITER_BACKWARD);
	if (iter == NULL)
		goto out;

	while (mnt_table_next_fs(table, iter, &fs) == 0)
		if (pmt_utabent_matches(vpt, fs)) {
			ret = 1;
			break;
		}
 out:
	mnt_free_context(ctx);
	return ret;
}

static bool fstype_networked(enum command_type fstype)
{
	switch (fstype) {
	case CMD_NFSMOUNT:
	case CMD_CIFSMOUNT:
	case CMD_SMBMOUNT:
	case CMD_NCPMOUNT:
		return true;
	default:
		return false;
	}
}

/**
 * vol_to_dev -
 * @vol:	volume to analyze
 *
 * Turn a volume into the mountspec as accepted by the specific mount program.
 */
hxmc_t *pmt_vol_to_dev(const struct vol *vol)
{
	hxmc_t *ret;

	switch (vol->type) {
	case CMD_SMBMOUNT:
	case CMD_CIFSMOUNT:
		if (vol->server != NULL) {
			ret = HXmc_strinit("//");
			HXmc_strcat(&ret, vol->server);
			HXmc_strcat(&ret, "/");
			HXmc_strcat(&ret, vol->volume);
		} else {
			ret = HXmc_strinit(vol->volume);
		}
		break;

	case CMD_NCPMOUNT:
		if (vol->server != NULL) {
			ret = HXmc_strinit(vol->server);
			HXmc_strcat(&ret, "/");
			HXmc_strcat(&ret, kvplist_get(&vol->options, "user"));
		} else {
			ret = HXmc_strinit(vol->volume);
		}
		break;

	case CMD_NFSMOUNT:
		if (vol->server != NULL) {
			ret = HXmc_strinit(vol->server);
			HXmc_strcat(&ret, ":");
			HXmc_strcat(&ret, vol->volume);
		} else {
			ret = HXmc_strinit(vol->volume);
		}
		break;

	default:
		if (!fstype_networked(vol->type) && vol->server != NULL)
			/*
			 * Possible causes: we do not know about the fs yet.
			 * (Was once the case with NFS4, for example.)
			 */
			l0g("The \"server\" attribute is ignored for this "
			    "filesystem (%s).\n", vol->fstype);

		ret = HXmc_strinit(vol->volume);
		break;
	}

	return ret;
}

static void log_pm_input(const struct config *const config,
    const struct vol *vpt)
{
	hxmc_t *options;

	options = kvplist_to_str(&vpt->options);
	w4rn(
		"Mount info: %s, user=%s <volume fstype=\"%s\" "
		"server=\"%s\" path=\"%s\" "
		"mountpoint=\"%s\" cipher=\"%s\" fskeypath=\"%s\" "
		"fskeycipher=\"%s\" fskeyhash=\"%s\" options=\"%s\" /> "
		"fstab=%u ssh=%u\n",
		vpt->globalconf ? "globalconf" : "luserconf",
		znul(vpt->user), znul(vpt->fstype),
		znul(vpt->server), znul(vpt->volume),
		vpt->mountpoint, znul(vpt->cipher), znul(vpt->fs_key_path),
		znul(vpt->fs_key_cipher), znul(vpt->fs_key_hash), options,
		vpt->use_fstab, vpt->uses_ssh
	);
	HXmc_free(options);
}

/**
 * mkmountpoint - create mountpoint for volume
 * @volume:	volume structure
 * @d:		directory to create
 *
 * Switches to the volume user's identity and see if we can create the
 * mountpoint. This is required for NFS mounts with root_squash enabled
 * (assuming the mountpoint's parent is writable by the user, e.g. if it is
 * inside the user's home directory).
 *
 * If that fails, do as usual (create as root, chown to user).
 */
static bool mkmountpoint(struct vol *volume, const char *d)
{
	const struct passwd *pe;
	hxmc_t *dtmp;
	char *last;
	bool ret = true;
	bool is_file;

	is_file = (kvplist_contains(&volume->options, "bind") ||
	          kvplist_contains(&volume->options, "move")) &&
	          pmt_fileop_isreg(volume->volume);

	if ((pe = getpwnam(volume->user)) == NULL) {
		l0g("getpwuid: %s\n", strerror(errno));
		return false;
	}
	dtmp = HXmc_strinit(d);
	if (dtmp == NULL || (!is_file && HXmc_strcat(&dtmp, "/") == NULL)) {
		l0g("HXmc_strinit: %s\n", strerror(errno));
		HXmc_free(dtmp);
		return false;
	}

	last = dtmp;
	while ((last = strchr(last + 1, '/')) != NULL) {
		*last = '\0';
		w4rn("%s: checking %s\n", __func__, dtmp);
		if (pmt_fileop_exists(dtmp)) {
			/* If it exists, all is good... */
			*last = '/';
			continue;
		}
		/*
		 * Prefer creation using user id, due to NFS possibly using
		 * root_squashed NFS.
		 *
		 * The directory will be created in a restricted mode S_IRWXU
		 * here. When mounted, the root directory of the new vfsmount
		 * will override it, so there is no need to use S_IRWXUGO or
		 * S_IRWXU | S_IXUGO here.
		 *
		 * Workaround for CIFS on root_squashed NFS: +S_IXUGO
		 */
		if (setegid(pe->pw_gid) < 0 ||
		    seteuid(pe->pw_uid) < 0) {
			l0g("seteuid/setegid %ld:%ld failed: %s\n",
			    static_cast(long, pe->pw_uid),
			    static_cast(long, pe->pw_gid), strerror(errno));
		} else if (mkdir(dtmp, S_IRWXU | S_IXUGO) == 0) {
			/* Was createable as user - ok */
			w4rn("mkdir[%ld] %s\n",
			     static_cast(long, pe->pw_uid), dtmp);
			*last = '/';
			continue;
		}
		/* Try with root again. */
		if (seteuid(0) < 0) {
			l0g("seteuid 0 failed\n");
			ret = false;
			break;
		}
		if (mkdir(dtmp, S_IRWXU | S_IXUGO) < 0) {
			l0g("mkdir %s failed: %s\n", dtmp, strerror(errno));
			ret = false;
			break;
		}
		w4rn("mkdir[0] %s\n", dtmp);
		if (chown(dtmp, pe->pw_uid, pe->pw_gid) < 0) {
			l0g("chown %s failed: %s\n", dtmp, strerror(errno));
			ret = false;
			break;
		}
		w4rn("chown %s -> %ld:%ld\n", dtmp,
		     static_cast(long, pe->pw_uid),
		     static_cast(long, pe->pw_gid));
		*last = '/';
	}
	HXmc_free(dtmp);

	/* Touch the file for bind mount */
	if (is_file && !pmt_fileop_exists(d)) {
		int fd = open(d, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
		if (fd < 0) {
			l0g("creat %s failed: %s\n", d, strerror(errno));
			ret = false;
			goto out;
		}
		close(fd);
		if (chown(d, pe->pw_uid, pe->pw_gid) < 0) {
			l0g("chown %s failed: %s\n", d, strerror(errno));
			ret = false;
		}
	}
	/* restore state: */
 out:
	seteuid(0);
	return volume->created_mntpt = ret;
}

/**
 * do_unmount -
 * @config:	current config
 * @vpt:	volume descriptor
 * @vinfo:
 * @password:	always %NULL
 *
 * Returns zero on error, positive non-zero for success.
 */
int do_unmount(const struct config *config, struct vol *vpt,
    struct HXformat_map *vinfo, const char *const password)
{
	struct HXdeque *argv;
	struct HXproc proc;
	int ret, type;

	assert(vinfo != NULL);
	assert(password == NULL);	/* password should point to NULL for unmounting */

	if (config->debug)
		/*
		 * Often, a process still exists with ~ as its pwd after
		 * logging out. Running ofl helps debug this.
		 */
		run_ofl(config, vpt->mountpoint, 0);

	switch (vpt->type) {
		case CMD_CRYPTMOUNT:
			type = CMD_CRYPTUMOUNT;
			break;
		case CMD_SMBMOUNT:
			type = CMD_SMBUMOUNT;
			break;
		case CMD_NCPMOUNT:
			type = CMD_NCPUMOUNT;
			break;
		case CMD_FUSEMOUNT:
			type = CMD_FUSEUMOUNT;
			break;
		default:
			type = CMD_UMOUNT;
			break;
	}

	if (config->command[type] == NULL || config->command[type]->first == 0)
		l0g("{smb,ncp}umount not defined in pam_count.conf.xml\n");

	argv = arglist_build(config->command[type], vinfo);
	memset(&proc, 0, sizeof(proc));
	proc.p_flags = HXPROC_VERBOSE | HXPROC_NULL_STDOUT | HXPROC_STDERR;
	proc.p_ops   = &pmt_dropprivs_ops;
	if ((ret = pmt_spawn_dq(argv, &proc)) <= 0) {
		ret = 0;
		goto out;
	}

	log_output(proc.p_stderr, "umount messages:\n");
	if ((ret = HXproc_wait(&proc)) >= 0)
		/* pass on through the result from the umount process */
		ret = proc.p_exited && proc.p_status == 0;

 out:
	if (vpt->created_mntpt && config->rmdir_mntpt)
		if (rmdir(vpt->mountpoint) < 0)
			/* non-fatal, but warn */
			w4rn("could not remove %s: %s\n", vpt->mountpoint,
			     strerror(errno));
	return ret;
}

static int check_filesystem(const struct config *config, const struct vol *vpt,
    struct HXformat_map *vinfo)
{
/* PRE:    config points to a valid struct config
 *         config->volume[vol] is a valid struct vol
 * POST:   integrity of volume has been checked
 * FN VAL: if error 0 else 1, errors are logged
 */
#if defined (__linux__)
	const char *fsck_target;
	struct HXdeque *argv;
	struct HXproc proc;
	int ret;

	assert(vinfo != NULL);

	if (vpt->type == CMD_CRYPTMOUNT)
		/*
		 * Cryptmount involves dm-crypt or LUKS, so using the raw
		 * device as fsck target is meaningless.
		 * So we do _not_ set FSCKTARGET in vinfo at all, and
		 * mount_set_fsck() depends on this behavior.
		 */
		return 0;

	fsck_target = vpt->volume;

	if (config->command[CMD_FSCK]->items == 0) {
		l0g("fsck not defined in pam_mount.conf.xml\n");
		return 0;
	}

	if (kvplist_contains(&vpt->options, "bind") ||
	    kvplist_contains(&vpt->options, "move") ||
	    fstype_nodev(vpt->fstype) != 0)
		return 1;

	format_add(vinfo, "FSCKTARGET", fsck_target);

	argv = arglist_build(config->command[CMD_FSCK], vinfo);
	memset(&proc, 0, sizeof(proc));
	proc.p_flags = HXPROC_VERBOSE | HXPROC_STDOUT | HXPROC_STDERR;
	if ((ret = pmt_spawn_dq(argv, &proc)) <= 0)
		return 0;

	/* stdout and stderr must be logged for fsck */
	log_output(proc.p_stdout, NULL);
	log_output(proc.p_stderr, NULL);
	w4rn("waiting for filesystem check\n");
	if ((ret = HXproc_wait(&proc)) < 0)
		l0g("error waiting for child: %s\n", strerror(-ret));

	/*
	 * pass on through the result -- okay if 0 (no errors) or 1 (errors
	 * corrected)
	 */
	return proc.p_exited && (proc.p_status == 0 || proc.p_status == 1);
#else
	l0g("checking filesystem not implemented on arch.\n");
	return 1;
#endif
}

/**
 * mount_set_fsck - set the FSCK environment variable for mount.crypt
 * @config:	configuration
 * @vol:	current volume
 * @vinfo:	variable substituions
 */
static void mount_set_fsck(const struct config *config,
    const struct vol *vol, struct HXformat_map *vinfo)
{
	const struct HXdeque_node *i;
	hxmc_t *string, *current;

	if (vol->type != CMD_CRYPTMOUNT)
		return;

	format_add(vinfo, "FSCKTARGET", "");
	string = HXmc_meminit(NULL, 0);

	for (i = config->command[CMD_FSCK]->first; i != NULL; i = i->next) {
		if (HXformat_aprintf(vinfo, &current, i->ptr) > 0) {
			HXmc_strcat(&string, current);
			HXmc_strcat(&string, " ");
		}
		HXmc_free(current);
	}

	setenv("FSCK", string, true);
	HXmc_free(string);
}

static void pmt_readfile(const char *file)
{
	hxmc_t *ln = NULL;
	FILE *fp;

	if ((fp = fopen(file, "r")) == NULL) {
		l0g("%s: Could not open %s: %s\n", __func__, file,
		    strerror(errno));
		return;
	}

	while (HX_getl(&ln, fp) != NULL) {
		HX_chomp(ln);
		l0g("%s\n", ln);
	}

	HXmc_free(ln);
	fclose(fp);
}

static int pmt_decrypt_keyfile(const struct vol *vol, const char *password,
    hxmc_t **result)
{
	struct ehd_keydec_request *dp;
	int ret;

	dp = ehd_kdreq_new();
	if (dp == NULL)
		return -errno;
	ret = ehd_kdreq_set(dp, EHD_KDREQ_KEYFILE, vol->fs_key_path);
	if (ret < 0)
		goto out;
	ret = ehd_kdreq_set(dp, EHD_KDREQ_DIGEST, vol->fs_key_hash);
	if (ret < 0)
		goto out;
	ret = ehd_kdreq_set(dp, EHD_KDREQ_CIPHER, vol->fs_key_cipher);
	if (ret < 0)
		goto out;
	ret = ehd_kdreq_set(dp, EHD_KDREQ_PASSWORD, password);
	if (ret < 0)
		goto out;
	ret = ehd_keydec_run(dp, result);
	if (ret == EHD_KEYDEC_NODIGEST)
		l0g("ehd_keydec_run: %s: \"%s\"\n", ehd_keydec_strerror(ret),
		    vol->fs_key_hash);
	else if (ret == EHD_KEYDEC_NOCIPHER)
		l0g("ehd_keydec_run: %s: \"%s\"\n", ehd_keydec_strerror(ret),
		    vol->fs_key_cipher);
	else if (ret != EHD_KEYDEC_SUCCESS)
		l0g("ehd_keydec_run: %s\n", ehd_keydec_strerror(ret));
 out:
	ehd_kdreq_free(dp);
	return ret;
}

/**
 * do_mount -
 * @config:	current config
 * @vpt:	volume descriptor
 * @vinfo:
 * @password:	login password (may be %NULL)
 *
 * Returns zero on error, positive non-zero for success.
 */
int do_mount(const struct config *config, struct vol *vpt,
    struct HXformat_map *vinfo, const char *password)
{
	const struct HXdeque_node *n;
	struct HXdeque *argv;
	struct HXproc proc;
	const char *mount_user;
	hxmc_t *ll_password = NULL;
	int ret;

	assert(vinfo != NULL);

	ret = pmt_already_mounted(config, vpt, vinfo);
	if (ret < 0) {
		l0g("could not determine if %s is already mounted, "
		    "failing\n", vpt->volume);
		return 0;
	} else if (ret > 0) {
		w4rn("%s already seems to be mounted at %s, "
		     "skipping\n", vpt->volume, vpt->mountpoint);
		return 1;
	}
	if (!pmt_fileop_exists(vpt->mountpoint)) {
		if (config->mkmntpoint) {
			if (!mkmountpoint(vpt, vpt->mountpoint))
				return 0;
		} else {
			l0g("mount point %s does not exist (pam_mount not "
			    "configured to make it)\n",
			    vpt->mountpoint);
			return 0;
		}
	}

	if (config->command[vpt->type]->items == 0) {
		l0g("proper mount command not defined in "
		    "pam_mount.conf.xml\n");
		return 0;
	}

	password = (password != NULL) ? password : "";
	if (vpt->type != CMD_CRYPTMOUNT && vpt->fs_key_cipher != NULL &&
	    strlen(vpt->fs_key_cipher) > 0) {
		/*
		 * Support keyfile together with non-CRYPTMOUNT volumes
		 * (e.g. CIFSMOUNT).
		 *
		 * In case of %CMD_CRYPTMOUNT, mount.crypt will deal with
		 * any openssl decryption. Without %CMD_CRYPTMOUNT however,
		 * we have to do this ourselves.
		 */
		w4rn("Not a crypto-type volume, but has keyfile and cipher. "
		     "Will decode OpenSSL key.\n");
		ret = pmt_decrypt_keyfile(vpt, password, &ll_password);
	} else {
		w4rn("Password will be sent to helper as-is.\n");
		ll_password = HXmc_strinit(password);
	}
	if (ll_password == NULL)
		return 0;

	if ((argv = HXdeque_init()) == NULL)
		l0g("malloc: %s\n", strerror(errno));
	if (vpt->uses_ssh)
		for (n = config->command[CMD_FD0SSH]->first;
		     n != NULL; n = n->next)
			arglist_add(argv, n->ptr, vinfo);

	for (n = config->command[vpt->type]->first; n != NULL; n = n->next)
		arglist_add(argv, n->ptr, vinfo);

	/*
	 * Note to future editors: Do not do a second-time substitution of the
	 * arguments. Variables specified within <volume>s are already expanded
	 * in expandconfig(), but see the comment in mount_op().
	 */

	if (vpt->type == CMD_LCLMOUNT &&
	    !check_filesystem(config, vpt, vinfo))
		l0g("error checking filesystem but will continue\n");
	/* send password down pipe to mount process */
	if (vpt->type == CMD_SMBMOUNT || vpt->type == CMD_CIFSMOUNT)
		setenv("PASSWD_FD", "0", 1);

	mount_set_fsck(config, vpt, vinfo);
	arglist_log(argv);
	mount_user = vpt->noroot ? vpt->user : NULL;
	memset(&proc, 0, sizeof(proc));
	proc.p_flags = HXPROC_VERBOSE | HXPROC_STDIN |
	               HXPROC_NULL_STDOUT | HXPROC_STDERR;
	proc.p_ops   = &pmt_dropprivs_ops;
	proc.p_data  = const_cast1(char *, mount_user);
	if ((ret = pmt_spawn_dq(argv, &proc)) <= 0) {
		HXmc_free(ll_password);
		return 0;
	}

	if (write(proc.p_stdin, ll_password, HXmc_length(ll_password)) !=
	    HXmc_length(ll_password))
		/* FIXME: clean: returns value of exit below */
		l0g("error sending password to mount\n");
	close(proc.p_stdin);
	HXmc_free(ll_password);

	log_output(proc.p_stderr, "Messages from underlying mount program:\n");
	if ((ret = HXproc_wait(&proc)) < 0) {
		l0g("error waiting for child: %s\n", strerror(-ret));
		return 0;
	}

	if ((!proc.p_exited || proc.p_status != 0) &&
	    vpt->created_mntpt && config->rmdir_mntpt) {
		/*
		 * Remove mountpoint if mount failed, to flag unavailability
		 * of service (e.g. when mntpt is the user's home directory).
		 */
		if (rmdir(vpt->mountpoint) < 0)
			/* non-fatal, but warn */
			w4rn("could not remove %s again: %s\n",
			     vpt->mountpoint, strerror(errno));
		vpt->created_mntpt = false;
	}

	if (config->debug) {
		if (pmt_fileop_exists("/proc/self/mountinfo"))
			pmt_readfile("/proc/self/mountinfo");
		else if (pmt_fileop_exists("/proc/self/mounts"))
			pmt_readfile("/proc/self/mounts");
		else if (pmt_fileop_exists("/proc/mounts"))
			pmt_readfile("/proc/mounts");
	}

	/* pass on through the result from the umount process */
	return proc.p_exited && proc.p_status == 0;
}

/**
 * mount_op -
 * @mnt:	function to execute mount operations (do_mount or do_unmount)
 * @config:	current configuration
 * @vpt:	volume descriptor
 * @password:	password string (may be %NULL on unmount)
 *
 * Returns zero on error, positive non-zero for success.
 * Note: Checked by volume_record_sane() and read_volume()
 */
int mount_op(mount_op_fn_t *mnt, const struct config *config,
    struct vol *vpt, const char *password)
{
	int fnval;
	struct HXformat_map *vinfo;
	struct passwd *pe;
	hxmc_t *options, *resmnt = NULL;

	/*
	 * This expansion (the other is in expandconfig()!) expands the mount
	 * command arguments (as defined in rdconf1.c) and should not be used
	 * to expand the <volume> attributes themselves.
	 *
	 * If you added an attribute, edit expandconfig instead.
	 * If you added a variable to the mount arg table in rdconf1.c,
	 * edit here. In fact, the @vinfo that is created below contains only
	 * arguments from the mount argument table.
	 */
	if ((vinfo = HXformat_init()) == NULL)
		return 0;

	HXmc_free(vpt->combopath);
	vpt->combopath = pmt_vol_to_dev(vpt);
	if (vpt->combopath == NULL) {
		l0g("vol_to_dev: %s\n", strerror(errno));
		return 0;
	}

	fnval = HX_realpath(&resmnt, vpt->mountpoint, HX_REALPATH_DEFAULT);
	if (fnval <= 0) {
		w4rn("Could not get realpath of %s: %s\n",
		     vpt->mountpoint, strerror(-fnval));
	} else {
		vpt->mountpoint = HX_strdup(resmnt);
		HXmc_free(resmnt);
	}

	format_add(vinfo, "MNTPT",    vpt->mountpoint);
	format_add(vinfo, "FSTYPE",   vpt->fstype);
	format_add(vinfo, "VOLUME",   vpt->volume);
	format_add(vinfo, "COMBOPATH", vpt->combopath);
	format_add(vinfo, "SERVER",   vpt->server);
	format_add(vinfo, "USER",     vpt->user);
	format_add(vinfo, "CIPHER",   vpt->cipher);
	format_add(vinfo, "FSKEYCIPHER", vpt->fs_key_cipher);
	format_add(vinfo, "FSKEYHASH",   vpt->fs_key_hash);
	format_add(vinfo, "FSKEYPATH",   vpt->fs_key_path);
	misc_add_ntdom(vinfo, vpt->user);

	if ((pe = getpwnam(vpt->user)) == NULL) {
		w4rn("getpwnam(\"%s\") failed: %s\n",
		     Config.user, strerror(errno));
	} else {
		HXformat_add(vinfo, "USERUID", reinterpret_cast(void *,
			static_cast(long, pe->pw_uid)),
			HXTYPE_UINT | HXFORMAT_IMMED);
		HXformat_add(vinfo, "USERGID", reinterpret_cast(void *,
			static_cast(long, pe->pw_gid)),
			HXTYPE_UINT | HXFORMAT_IMMED);
	}

	options = kvplist_to_str(&vpt->options);
	HXformat_add(vinfo, "OPTIONS", options, HXTYPE_STRING | HXFORMAT_IMMED);

	if (config->debug)
		log_pm_input(config, vpt);

	fnval = (*mnt)(config, vpt, vinfo, password);
	HXmc_free(options);
	HXformat_free(vinfo);
	return fnval;
}

/**
 * fstype_nodev -
 * @name:	fstype to check
 *
 * Returns 1 if the filesystem does not require a block device, 0 if it does
 * require a block device, -1 if we could not find out.
 */
int fstype_nodev(const char *name)
{
	char buf[80];
	FILE *fp;

	if (name == NULL)
		return 0;
	if ((fp = fopen("/proc/filesystems", "r")) == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *bp = buf;
		HX_chomp(buf);
		while (!HX_isspace(*bp) && *bp != '\0')
			++bp;
		while (HX_isspace(*bp))
			++bp;
		if (strcasecmp(bp, name) == 0) {
			fclose(fp);
			return strncasecmp(buf, "nodev", 5) == 0;
		}
	}

	fclose(fp);
	return -1;
}

/**
 * umount_final - called when the last session has exited
 *
 * Send signals to processes and then unmount.
 */
void umount_final(struct config *config)
{
	struct vol *vol;

	if (HXlist_empty(&config->volume_list.list))
		/* Avoid needlessy waiting on usleep */
		return;

	if (config->sig_hup)
		HXlist_for_each_entry_rev(vol, &config->volume_list, list)
			run_ofl(config, vol->mountpoint, SIGHUP);
	if (config->sig_term) {
		usleep(config->sig_wait);
		HXlist_for_each_entry_rev(vol, &config->volume_list, list)
			run_ofl(config, vol->mountpoint, SIGTERM);
	}
	if (config->sig_kill) {
		usleep(config->sig_wait);
		HXlist_for_each_entry_rev(vol, &config->volume_list, list)
			run_ofl(config, vol->mountpoint, SIGKILL);
	}
	HXlist_for_each_entry_rev(vol, &config->volume_list, list) {
		w4rn("going to unmount\n");
		if (!mount_op(do_unmount, config, vol, NULL))
			l0g("unmount of %s failed\n",
			    vol->volume);
	}
}

/**
 * fstype_icase - return whether the volume name is case-insensitive
 * @fstype:	filesystem type (cifs, etc.)
 *
 * For some filesystems, notably those which do not distinguish between case
 * sensitivity, the volume ("share") name is usually also case-insensitive.
 */
bool fstype_icase(const char *fstype)
{
	if (fstype == NULL)
		return false;
	return strcasecmp(fstype, "cifs") == 0 ||
	       strcasecmp(fstype, "smbfs") == 0 ||
	       strcasecmp(fstype, "ncpfs") == 0;
}

bool fstype2_icase(enum command_type fstype)
{
	switch (fstype) {
	case CMD_CIFSMOUNT:
	case CMD_SMBMOUNT:
	case CMD_NCPMOUNT:
		return true;
	default:
		return false;
	}
}
