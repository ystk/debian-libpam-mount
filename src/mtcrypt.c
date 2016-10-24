/*
 *	Copyright Jan Engelhardt, 2008-2011
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <sys/mount.h>
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
#include <libHX.h>
#include "libcryptmount.h"
#include "pam_mount.h"
#ifdef HAVE_LIBCRYPTO
#	include <openssl/evp.h>
#endif
#include "cmt-internal.h"

/**
 * @object:		volume or mountpoint; used by remount
 * @container:		path to the volume (like (bdev) /dev/sda2 or
 * 			(file) /home/user.!@#)
 * @crypto_name:	preferred name of the crypto device (where possible)
 * @mountpoint:		where to put this
 * @extra_options:	options to pass down
 * @no_update:		do not update mtab
 * @loop_device:	loop device association, if any
 * @crypto_device:	crypto device
 * @trunc_keysize:	override cryptsetup keysize
 * 			(needed for ASCII keys, see SF#2727353)
 * @is_cont:		looks like a container; used by remount
 * @blkdev:		true if @container is a block device
 * @fsck:		true if fsck should be performed
 * @remount:		issue a remount
 * @allow_discards:	set block device to allow fs trim requests
 */
struct mount_options {
	hxmc_t *object, *container, *mountpoint;
	const char *fstype;
	const char *crypto_name, *dmcrypt_cipher, *dmcrypt_hash;
	const char *fsk_hash, *fsk_cipher, *fsk_file;
	hxmc_t *fsk_password, *extra_opts, *crypto_device;
	char *loop_device;
	unsigned int no_update, readonly, trunc_keysize;
	bool is_cont;
	bool blkdev;
	bool fsck;
	bool remount;
	bool allow_discards;
};

/**
 * @object:		what umount should look for
 * @no_update:		skip updating mtab
 * @ro_fallback:	remount read-only on umount error
 * @is_cont:		@object denotes the container
 * @blkdev:		@container is a block device
 */
struct umount_options {
	hxmc_t *object;
	unsigned int no_update, ro_fallback;
	bool is_cont, blkdev;
};

static unsigned int mtcr_debug;

static void mtcr_parse_suboptions(const struct HXoptcb *cbi)
{
	struct mount_options *mo = cbi->current->uptr;
	hxmc_t *passthru;
	bool first = true;
	char *copt;
	char *key;
	int ret;

	if ((copt = xstrdup(cbi->data)) == NULL)
		return;
	if ((passthru = HXmc_meminit(NULL, strlen(copt))) == NULL)
		abort();

	while ((key = HX_strsep(&copt, ",")) != NULL) {
		char *value = strchr(key, '=');

		if (value != NULL)
			*value++ = '\0';
		while (HX_isspace(*key))
			++key;
		if (strcmp(key, "cipher") == 0) {
			mo->dmcrypt_cipher = value;
			ret = ehd_cipherdigest_security(value);
			if (ret < 0)
				fprintf(stderr, "%s\n", strerror(-ret));
			else if (ret < EHD_SECURITY_UNSPEC)
				fprintf(stderr, "Cipher \"%s\" is considered "
				        "insecure.\n", value);
		} else if (strcmp(key, "fsk_cipher") == 0) {
			mo->fsk_cipher = value;
			ret = ehd_cipherdigest_security(value);
			if (ret < 0)
				fprintf(stderr, "%s\n", strerror(-ret));
			else if (ret < EHD_SECURITY_UNSPEC)
				fprintf(stderr, "Cipher \"%s\" is considered "
				        "insecure.\n", value);
		} else if (strcmp(key, "fsk_hash") == 0) {
			mo->fsk_hash = value;
			ret = ehd_cipherdigest_security(value);
			if (ret < 0)
				fprintf(stderr, "%s\n", strerror(-ret));
			else if (ret < EHD_SECURITY_UNSPEC)
				fprintf(stderr, "Hash \"%s\" is considered "
				        "insecure.\n", value);
		} else if (strcmp(key, "fstype") == 0)
			mo->fstype = value;
		else if (strcmp(key, "keyfile") == 0)
			mo->fsk_file = value;
		else if (strcmp(key, "keysize") == 0)
			mo->trunc_keysize = strtoul(value, NULL, 0) / CHAR_BIT;
		else if (strcmp(key, "fsck") == 0)
			mo->fsck = true;
		else if (strcmp(key, "loop") == 0)
			/* automatically detected anyway */
			l0g("loop mount option ignored\n");
		else if (strcmp(key, "hash") == 0) {
			mo->dmcrypt_hash = value;
			ret = ehd_cipherdigest_security(value);
			if (ret < 0)
				fprintf(stderr, "%s\n", strerror(-ret));
			else if (ret < EHD_SECURITY_UNSPEC)
				fprintf(stderr, "Hash \"%s\" is considered "
				        "insecure.\n", value);
		} else if (strcmp(key, "verbose") == 0) {
			if (!mtcr_debug)
				ehd_logctl(EHD_LOGFT_DEBUG, EHD_LOG_SET);
			mtcr_debug = true;
		} else if (strcmp(key, "crypto_name") == 0) {
			mo->crypto_name = value;
		} else if (strcmp(key, "allow_discard") == 0) {
			mo->allow_discards = true;
		} else {
			/*
			 * Above are the pam_mount-specific options that are
			 * "eaten". Everything else is passed right on to
			 * mount(8).
			 */
			if (!first)
				HXmc_strcat(&passthru, ",");
			first = false;
			HXmc_strcat(&passthru, key);
			if (value != NULL) {
				HXmc_strcat(&passthru, "=");
				HXmc_strcat(&passthru, value);
			}
		}

		/*
		 * As the following options are not listed in the above cases,
		 * these did get added to passthrough. We still need to
		 * inspect them, however.
		 */
		if (strcmp(key, "remount") == 0)
			mo->remount = true;
		else if (strcmp(key, "ro") == 0)
			mo->readonly = EHD_LOSETUP_RO;
		else if (strcmp(key, "rw") == 0)
			mo->readonly = EHD_LOSETUP_RW;
		else if (strcmp(key, "discard") == 0)
			mo->allow_discards = true;
	}

	if (*passthru != '\0') {
		if (mo->extra_opts == NULL) {
			mo->extra_opts = passthru;
		} else if (*mo->extra_opts != '\0') {
			HXmc_strcat(&mo->extra_opts, ",");
			HXmc_strcat(&mo->extra_opts, passthru);
			HXmc_free(passthru);
		}
	} else {
		HXmc_free(passthru);
	}
}

/**
 * keyfile passthru (kfpt)
 */
static bool kfpt_selected(const char *c)
{
	return c != NULL && strcmp(c, "none") == 0;
}

static bool mtcr_get_mount_options(int *argc, const char ***argv,
    struct mount_options *opt)
{
	struct stat sb;
	struct HXoption options_table[] = {
		{.sh = 'n', .type = HXTYPE_NONE, .ptr = &opt->no_update,
		 .help = "Do not update /etc/mtab"},
		{.sh = 'o', .type = HXTYPE_STRING, .cb = mtcr_parse_suboptions,
		 .uptr = opt, .help = "Mount options"},
		{.sh = 'r', .type = HXTYPE_NONE, .ptr = &opt->readonly,
		 .help = "Set up devices and mounts as read-only"},
		{.sh = 'v', .type = HXTYPE_NONE, .ptr = &mtcr_debug,
		 .help = "Enable debugging"},
		HXOPT_AUTOHELP,
		HXOPT_TABLEEND,
	};
	bool kfpt;
	int ret;

	if (HX_getopt(options_table, argc, argv, HXOPT_USAGEONERR) !=
	    HXOPT_ERR_SUCCESS)
		return false;

	if (mtcr_debug)
		ehd_logctl(EHD_LOGFT_DEBUG, EHD_LOG_SET);

	if (opt->remount) {
		if (*argc < 2 || *(*argv)[1] == '\0') {
			fprintf(stderr, "%s: You need to specify the container "
			        "or its mountpoint\n", **argv);
			return false;
		}

		/* Only absolute paths should be in mtab. */
		ret = HX_realpath(&opt->object, (*argv)[1],
		      HX_REALPATH_DEFAULT | HX_REALPATH_ABSOLUTE);
		if (ret < 0) {
			fprintf(stderr, "realpath %s: %s\n",
			        (*argv)[1], strerror(-ret));
			return false;
		}
		if (stat(opt->object, &sb) < 0) {
			/* If it does not exist, it cannot be the container. */
			opt->is_cont = false;
			if (errno != ENOENT) {
				fprintf(stderr, "stat %s: %s\n", opt->object,
				        strerror(errno));
				return false;
			}
		} else {
			/* If it is a directory, it cannot be the container either. */
			if (!S_ISDIR(sb.st_mode))
				opt->is_cont = true;
			if (S_ISBLK(sb.st_mode))
				opt->blkdev = true;
		}

		return true;
	}

	if (*argc < 2 || *(*argv)[1] == '\0') {
		fprintf(stderr, "%s: You need to specify the device to mount\n",
		        **argv);
		return false;
	}
	if (*argc < 3 || *(*argv)[2] == '\0') {
		fprintf(stderr, "%s: You need to specify the mountpoint\n",
		        **argv);
		return false;
	}

	ret = HX_realpath(&opt->container, (*argv)[1],
	      HX_REALPATH_DEFAULT | HX_REALPATH_ABSOLUTE);
	if (ret < 0) {
		fprintf(stderr, "realpath %s: %s\n",
		        (*argv)[1], strerror(-ret));
		return false;
	}
	ret = HX_realpath(&opt->mountpoint, (*argv)[2],
	      HX_REALPATH_DEFAULT | HX_REALPATH_ABSOLUTE);
	if (ret < 0) {
		fprintf(stderr, "realpath %s: %s\n",
		        (*argv)[2], strerror(-ret));
		return false;
	}

	if (stat(opt->mountpoint, &sb) < 0) {
		fprintf(stderr, "%s: stat %s: %s\n", **argv, opt->mountpoint,
		        strerror(errno));
		return false;
	} else if (!S_ISDIR(sb.st_mode)) {
		fprintf(stderr, "%s: %s is not a directory\n",
		        **argv, opt->mountpoint);
		return false;
	}

	if (stat(opt->container, &sb) < 0) {
		fprintf(stderr, "%s: stat %s: %s\n", **argv, opt->container,
		        strerror(errno));
		return false;
	} else if (S_ISBLK(sb.st_mode)) {
		opt->blkdev = true;
	} else if (!S_ISREG(sb.st_mode)) {
		fprintf(stderr, "%s: %s must either be a regular file or "
		        "block device\n", **argv, opt->container);
		return false;
	}

	kfpt = kfpt_selected(opt->fsk_cipher);
	if (opt->fsk_file == NULL) {
		if (opt->fsk_cipher != NULL)
			fprintf(stderr, "%s: fsk_cipher is ignored because no "
			        "keyfile given\n", **argv);
		if (opt->fsk_hash != NULL)
			fprintf(stderr, "%s: fsk_hash is ignored because no "
			        "keyfile given\n", **argv);
	} else {
		if (opt->fsk_cipher == NULL) {
			fprintf(stderr, "%s: No openssl cipher specified "
			        "(use -o fsk_cipher=xxx)\n", **argv);
			return false;
		} else if (!kfpt && opt->fsk_hash == NULL) {
			fprintf(stderr, "%s: No openssl hash specified "
			        "(use -o fsk_hash=xxx)\n", **argv);
			return false;
		}
	}

	ret = ehd_is_luks(opt->container, opt->blkdev);
	if (ret > 0) {
		/* LUKS */
		if (opt->dmcrypt_cipher != NULL)
			fprintf(stderr, "%s: dmcrypt cipher ignored for LUKS "
			        "volumes\n", **argv);
		if (opt->dmcrypt_hash != NULL)
			fprintf(stderr, "%s: dmcrypt hash ignored for LUKS "
			        "volumes\n", **argv);
	} else if (ret == 0) {
		/* PLAIN */
		if (opt->dmcrypt_cipher == NULL) {
			fprintf(stderr, "%s: No dmcrypt cipher specified "
			        "(use -o cipher=xxx)\n", **argv);
			return false;
		}
	}

	if (opt->dmcrypt_hash == NULL)
		opt->dmcrypt_hash = "plain";
	if (!kfpt)
		opt->fsk_password = ehd_get_password(NULL);
	return true;
}

static hxmc_t *mtcr_slurp_file(const char *file)
{
	struct stat sb;
	char tmp[4096];
	hxmc_t *buf;
	int fd;

	if ((fd = open(file, O_RDONLY | O_BINARY)) < 0) {
		fprintf(stderr, "Could not open %s: %s\n",
		        file, strerror(errno));
		return NULL;
	}

	if (fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode))
		buf = HXmc_meminit(NULL, sb.st_size);
	else
		buf = HXmc_meminit(NULL, 4096 / CHAR_BIT);

	if (buf == NULL) {
		fprintf(stderr, "%s: %s\n", __func__, strerror(errno));
	} else {
		ssize_t ret;
		while ((ret = read(fd, tmp, sizeof(tmp))) > 0)
			HXmc_memcat(&buf, tmp, ret);
	}
	close(fd);
	return buf;
}

static int mtcr_decrypt_keyfile(const struct mount_options *opt,
    hxmc_t **result)
{
	struct ehd_keydec_request *dp;
	int ret;

	dp = ehd_kdreq_new();
	if (dp == NULL)
		return -errno;
	ret = ehd_kdreq_set(dp, EHD_KDREQ_KEYFILE, opt->fsk_file);
	if (ret < 0)
		goto out;
	ret = ehd_kdreq_set(dp, EHD_KDREQ_DIGEST, opt->fsk_hash);
	if (ret < 0)
		goto out;
	ret = ehd_kdreq_set(dp, EHD_KDREQ_CIPHER, opt->fsk_cipher);
	if (ret < 0)
		goto out;
	ret = ehd_kdreq_set(dp, EHD_KDREQ_PASSWORD, opt->fsk_password);
	if (ret < 0)
		goto out;
	ret = ehd_keydec_run(dp, result);
 out:
	ehd_kdreq_free(dp);
	return ret;
}

static int mtcr_fsck(struct ehd_mount_request *rq,
    struct ehd_mount_info *mtinfo)
{
	const char *const fsck_args[4] =
		{"fsck", "-p", mtinfo->crypto_device, NULL};
	int ret;

	arglist_llog(fsck_args);
	ret = HXproc_run_sync(fsck_args, HXPROC_VERBOSE);
	/*
	 * Return codes higher than 1 indicate that manual intervention
	 * is required, therefore abort the mount/login.
	 * Lower than 0: internal error (e.g. fork).
	 */
	if (ret != 0 && ret != 1)
		fprintf(stderr, "Automatic fsck failed, manual intervention "
		        "required, run_status/exit status %d\n", ret);
	return ret == 0;
}

/**
 * mtcr_mount
 *
 * Returns positive non-zero for success.
 */
static int mtcr_mount(struct mount_options *opt)
{
	const char *mount_args[8];
	hxmc_t *key = NULL;
	int ret, argk;
	struct ehd_mount_info *mount_info;
	struct ehd_mount_request *mount_request;
	unsigned int key_size = 0, trunc_keysize;

	mount_request = ehd_mtreq_new();
	if (mount_request == NULL) {
		fprintf(stderr, "%s\n", strerror(errno));
		return 0;
	}
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_CONTAINER, opt->container);
	if (ret < 0)
		goto out_r;
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_CRYPTONAME, opt->crypto_name);
	if (ret < 0)
		goto out_r;
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_FS_CIPHER, opt->dmcrypt_cipher);
	if (ret < 0)
		goto out_r;
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_FS_HASH, opt->dmcrypt_hash);
	if (ret < 0)
		goto out_r;
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_READONLY, opt->readonly);
	if (ret < 0)
		goto out_r;
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_ALLOW_DISCARDS,
	      opt->allow_discards);
	if (ret < 0)
		goto out_r;
	/* Hack for CRYPT_PLAIN: default to 256 */
	trunc_keysize = 256 / CHAR_BIT;
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_TRUNC_KEYSIZE, trunc_keysize);
	if (ret < 0)
		goto out_r;

	if (opt->fsk_file == NULL) {
		/* LUKS derives the key material on its own */
		ret = ehd_mtreq_set(mount_request, EHD_MTREQ_KEY_SIZE, HXmc_length(opt->fsk_password));
		if (ret < 0)
			goto out_r;
		ret = ehd_mtreq_set(mount_request, EHD_MTREQ_KEY_DATA, opt->fsk_password);
		if (ret < 0)
			goto out_r;
		/* Leave trunc_keysize at 0 */
	} else if (kfpt_selected(opt->fsk_cipher)) {
		key = mtcr_slurp_file(opt->fsk_file);
		if (key == NULL) {
			ret = -errno;
			goto out_r;
		}
	} else {
		ret = mtcr_decrypt_keyfile(opt, &key);
		if (ret != EHD_KEYDEC_SUCCESS || key == NULL) {
			fprintf(stderr, "Error while decrypting fskey: %s\n",
			        ehd_keydec_strerror(ret));
			goto out_z;
		}
	}

	if (key != NULL) {
		key_size = HXmc_length(key);
		ret = ehd_mtreq_set(mount_request, EHD_MTREQ_TRUNC_KEYSIZE, key_size);
		if (ret < 0)
			goto out_r;
		ret = ehd_mtreq_set(mount_request, EHD_MTREQ_KEY_SIZE, key_size);
		if (ret < 0)
			goto out_r;
		ret = ehd_mtreq_set(mount_request, EHD_MTREQ_KEY_DATA, key);
		HXmc_free(key);
		key = NULL;
		if (ret < 0)
			goto out_r;
	}
	if (opt->trunc_keysize != 0) {
		ret = ehd_mtreq_set(mount_request, EHD_MTREQ_TRUNC_KEYSIZE, opt->trunc_keysize);
		if (ret < 0)
			goto out_r;
	}
	if (opt->fsck) {
		ret = ehd_mtreq_set(mount_request, EHD_MTREQ_CRYPTO_HOOK,
		      mtcr_fsck);
		if (ret < 0)
			goto out_r;
	}

	w4rn("keysize=%u trunc_keysize=%u\n", key_size, trunc_keysize);
	if ((ret = ehd_load(mount_request, &mount_info)) < 0) {
		fprintf(stderr, "ehd_load: %s\n", strerror(errno));
		goto out_z;
	} else if (ret == 0) {
		goto out_z;
	}

	/* candidate for replacement by some libmount calls, I guess. */
	argk = 0;
	mount_args[argk++] = "mount";
	if (opt->fstype != NULL) {
		mount_args[argk++] = "-t";
		mount_args[argk++] = opt->fstype;
	}
	if (opt->extra_opts != NULL) {
		mount_args[argk++] = "-o";
		mount_args[argk++] = opt->extra_opts;
	}
	mount_args[argk++] = mount_info->crypto_device;
	mount_args[argk++] = opt->mountpoint;
	mount_args[argk] = NULL;

	assert(argk < ARRAY_SIZE(mount_args));
	arglist_llog(mount_args);
	if ((ret = HXproc_run_sync(mount_args, HXPROC_VERBOSE)) != 0) {
		fprintf(stderr, "mount failed with run_sync status %d\n", ret);
		ehd_unload(mount_info);
		ret = 0;
		goto out_i;
	}
	ret = HX_realpath(&mount_info->mountpoint, opt->mountpoint,
	      HX_REALPATH_DEFAULT | HX_REALPATH_ABSOLUTE);
	if (ret <= 0)
		goto out_i;
	if ((ret = pmt_cmtab_add(mount_info)) <= 0) {
		fprintf(stderr, "pmt_cmtab_add: %s\n", strerror(errno));
		/* ignore error on cmtab - let user have his crypto */
	} else if (opt->no_update) {
		/* awesome logic */;
	} else {
		pmt_smtab_add(mount_info->container, mount_info->mountpoint,
			"crypt", (opt->extra_opts != NULL) ?
			opt->extra_opts : "defaults");
	}

 out_i:
	ehd_mtinfo_free(mount_info);
	return ret;

 out_r:
	fprintf(stderr, "ehd_mtreq_set: %s\n", strerror(-ret));
 out_z:
	HXmc_free(key);
	return 0;
}

static bool mtcr_get_umount_options(int *argc, const char ***argv,
    struct umount_options *opt)
{
	struct stat sb;
	struct HXoption options_table[] = {
		{.sh = 'f', .type = HXTYPE_NONE,
		 .help = "(Option ignored)"},
		{.sh = 'n', .type = HXTYPE_NONE, .ptr = &opt->no_update,
		 .help = "Do not update /etc/mtab"},
		{.sh = 'r', .type = HXTYPE_NONE, .ptr = &opt->ro_fallback,
		 .help = "(Option ignored)"},
		{.sh = 'v', .type = HXTYPE_NONE, .ptr = &mtcr_debug,
		 .help = "Be verbose - enable debugging"},
		HXOPT_AUTOHELP,
		HXOPT_TABLEEND,
	};
	int ret;

	if (HX_getopt(options_table, argc, argv, HXOPT_USAGEONERR) !=
	    HXOPT_ERR_SUCCESS)
		return false;

	if (mtcr_debug)
		ehd_logctl(EHD_LOGFT_DEBUG, EHD_LOG_SET);

	if (*argc < 2 || *(*argv)[1] == '\0') {
		fprintf(stderr, "%s: You need to specify the container "
		        "or its mountpoint\n", **argv);
		return false;
	}

	ret = HX_realpath(&opt->object, (*argv)[1],
	      HX_REALPATH_DEFAULT | HX_REALPATH_ABSOLUTE);
	if (ret < 0) {
		fprintf(stderr, "realpath %s: %s\n",
		        (*argv)[1], strerror(-ret));
		return false;
	}
	if (stat(opt->object, &sb) < 0) {
		/* If it does not exist, it cannot be the container. */
		opt->is_cont = false;
		if (errno != ENOENT) {
			fprintf(stderr, "stat %s: %s\n", opt->object,
			        strerror(errno));
			return false;
		}
	} else {
		/* If it is a directory, it cannot be the container either. */
		if (!S_ISDIR(sb.st_mode))
			opt->is_cont = true;
		if (S_ISBLK(sb.st_mode))
			opt->blkdev = true;
	}

	return true;
}

/**
 * mtcr_remount - remount the actual FS
 */
static int mtcr_remount(struct mount_options *opt)
{
	const char *rmt_args[5];
	int ret, argk = 0;
	char *mntpt, *cont;

	ret = pmt_cmtab_get(opt->object, opt->is_cont ?
	      CMTABF_CONTAINER : CMTABF_MOUNTPOINT, &mntpt, &cont, NULL, NULL);
	if (ret == 0) {
		fprintf(stderr, "Nothing found that could be remounted.\n");
		return 1;
	} else if (ret < 0) {
		fprintf(stderr, "pmt_cmtab_get: %s\n", strerror(-ret));
		return ret;
	}

	if (!opt->no_update)
		pmt_smtab_remove(mntpt, SMTABF_MOUNTPOINT);
	rmt_args[argk++] = "mount";
	rmt_args[argk++] = "-o";
	rmt_args[argk++] = opt->extra_opts;
	rmt_args[argk++] = mntpt;
	rmt_args[argk]   = NULL;
	assert(argk < ARRAY_SIZE(rmt_args));

	ret = HXproc_run_sync(rmt_args, HXPROC_VERBOSE);
	if (ret != 0)
		fprintf(stderr, "remount %s failed with run_sync status %d\n",
		        opt->object, ret);

	if (!opt->no_update)
		pmt_smtab_add(cont, mntpt, "crypt", (opt->extra_opts != NULL) ?
			opt->extra_opts : "defaults");
	free(mntpt);
	free(cont);
	return ret;
}

/**
 */
static void mtcr_log_contents(const char *file)
{
	hxmc_t *ln = NULL;
	FILE *fp;

	if (file == NULL)
		return;
	w4rn("Dumping contents of %s\n", file);
	if ((fp = fopen(file, "r")) == NULL) {
		w4rn("Failed to open %s: %s\n", file, strerror(errno));
		return;
	}
	while (HX_getl(&ln, fp) != NULL) {
		HX_chomp(ln);
		w4rn("%s\n", ln);
	}
	HXmc_free(ln);
	fclose(fp);
}

/**
 * mtcr_umount - unloads the EHD from mountpoint
 *
 * Returns positive non-zero for success.
 */
static int mtcr_umount(struct umount_options *opt)
{
	const char *umount_args[3];
	int final_ret, ret, argk = 0;
	struct ehd_mount_info mount_info;
	char *mountpoint = NULL;

	memset(&mount_info, 0, sizeof(mount_info));
	ret = pmt_cmtab_get(opt->object, opt->is_cont ? CMTABF_CONTAINER :
	      CMTABF_MOUNTPOINT, &mountpoint, &mount_info.container,
	      &mount_info.loop_device, &mount_info.crypto_device);
	if (ret < 0) {
		fprintf(stderr, "pmt_cmtab_get: %s\n", strerror(-ret));
		return 0;
	} else if (ret == 0) {
		fprintf(stderr, "No vfsmount found while searching for \"%s\" "
		        "as a container file, or as a mountpoint. (According "
		        "to the intersection of cmtab (%s) with smtabs)\n",
		        opt->object, pmt_cmtab_path());
		mtcr_log_contents(pmt_cmtab_path());
		mtcr_log_contents(pmt_smtab_path());
		mtcr_log_contents(pmt_kmtab_path());
		return 1;
	} else {
		if (ret & PMT_BY_CONTAINER)
			w4rn("Found container in smtab\n");
		if (ret & PMT_BY_CRYPTODEV)
			w4rn("Found crypto device in smtab\n");
	}

	if (!opt->no_update)
		pmt_smtab_remove(mountpoint, SMTABF_MOUNTPOINT);
	pmt_cmtab_remove(mountpoint);

	umount_args[argk++] = "umount";
	umount_args[argk++] = mountpoint;
	umount_args[argk]   = NULL;

	assert(argk < ARRAY_SIZE(umount_args));
	arglist_llog(umount_args);
	if ((final_ret = HXproc_run_sync(umount_args, HXPROC_VERBOSE)) != 0) {
		fprintf(stderr, "umount %s failed with run_sync status %d\n",
		        opt->object, ret);
		final_ret = 0;
		ehd_unload(&mount_info);
	} else if ((ret = ehd_unload(&mount_info)) <= 0) {
		fprintf(stderr, "ehd_unload: %s\n", strerror(-ret));
		final_ret = 0;
	} else {
		final_ret = 1;
	}

	return final_ret;
}

static int main2(int argc, const char **argv)
{
	ehd_logctl(EHD_LOGFT_NOSYSLOG, EHD_LOG_SET);
	setenv("PATH", PMT_DFL_PATH, true);
	/*
	 * When invoking umount.crypt via the libtool helper script,
	 * argv[0] is always "mount.crypt" due to the symlinking.
	 */
	if (strncmp(HX_basename(*argv), "umount", 6) == 0 ||
	    getenv("PMT_DEBUG_UMOUNT") != NULL) {
		struct umount_options opt;

		memset(&opt, 0, sizeof(opt));
		if (!mtcr_get_umount_options(&argc, &argv, &opt))
			return EXIT_FAILURE;

		return mtcr_umount(&opt) > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
	} else {
		struct mount_options opt;

		memset(&opt, 0, sizeof(opt));
		if (!mtcr_get_mount_options(&argc, &argv, &opt))
			return EXIT_FAILURE;

		if (opt.remount)
			return (mtcr_remount(&opt) > 0) ?
			       EXIT_SUCCESS : EXIT_FAILURE;
		else
			return (mtcr_mount(&opt) > 0) ?
			       EXIT_SUCCESS : EXIT_FAILURE;
	}

	return EXIT_FAILURE;
}

int main(int argc, const char **argv)
{
	struct stat sb;
	int ret;

	if (stat("/etc/mtab", &sb) == 0 && (sb.st_mode & S_IWUGO) == 0)
		fprintf(stderr, "NOTE: mount.crypt does not support utab "
		        "(systems with no mtab or read-only mtab) yet. This "
		        "means that you will temporarily need to call "
		        "umount.crypt(8) rather than umount(8) to get crypto "
		        "volumes unmounted.\n");

	ret = HX_init();
	if (ret <= 0) {
		fprintf(stderr, "HX_init: %s\n", strerror(errno));
		abort();
	}
	ret = cryptmount_init();
	if (ret <= 0) {
		fprintf(stderr, "cryptmount_init: %s\n", strerror(errno));
		abort();
	}

	ret = main2(argc, argv);
	cryptmount_exit();
	HX_exit();
	return ret;
}
