/*
 *	Encrypted Home Disk manipulation utility
 *	Copyright Jan Engelhardt, 2008-2011
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#define _GNU_SOURCE 1
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libHX/ctype_helper.h>
#include <libHX/defs.h>
#include <libHX/init.h>
#include <libHX/misc.h>
#include <libHX/option.h>
#include <libHX/proc.h>
#include <libHX/string.h>
#include <security/pam_appl.h>
#include <libcryptsetup.h>
#include <pwd.h>
#include "libcryptmount.h"
#include "pam_mount.h"

static const char ehd_default_dmcipher[] = "aes-cbc-essiv:sha256";
static const unsigned int ehd_default_strength = 256; /* cipher, not ESSIV */
static const char ehd_default_hash[] = "sha512"; /* for PBKDF2 */
static unsigned int ehd_debug;

/**
 * @size:		container size in bytes
 * @path:		store container at this path
 * @fstype:		initialize container with this filesystem
 * @cipher:		cipher specification as understood by cryptsetup
 * @keybits:		block size, as understood by cryptsetup and the cipher
 * @skip_random:	do not fill with random data
 * @blkdev:		whether @path is a block device
 */
struct container_ctl {
	unsigned long long size;
	char *path, *fstype, *cipher, *hash, *user;
	unsigned int keybits, skip_random, uid;
	bool blkdev;
};

/**
 * struct ehd_ctl - program control block
 * @force_level:	number of "-f"s passed
 * @interactive:	if stdin is a tty
 * @cont:		container control substructure
 * @password:		master key password
 */
struct ehd_ctl {
	unsigned int force_level;
	struct container_ctl cont;
	const char *password;
	bool interactive;
};

static bool ehd_check(const struct ehd_ctl *pg)
{
	const struct container_ctl *cont = &pg->cont;
	int ret, ask = 0;
	struct stat sb;
	bool exists;

	printf("Creating a new container at %s\n", cont->path);

	/* First, check for hideous symlinks */
	if (lstat(cont->path, &sb) < 0) {
		if (errno == ENOENT) {
			exists = false;
		} else {
			perror("lstat");
			return false;
		}
	} else {
		exists = true;
	}

	if (exists && S_ISLNK(sb.st_mode)) {
		hxmc_t *target = NULL;

		/* Get confirmation for overwriting files */
		++ask;
		ret = HX_readlink(&target, cont->path);
		if (ret < 0) {
			fprintf(stderr, "readlink %s: %s\n",
			        cont->path, strerror(-ret));
			return false;
		}
		printf("%s is a symlink and points to %s\n",
		       cont->path, target);
		HXmc_free(target);
		/* Get extra confirmation */
		++ask;

		/* Now check for underlying device */
		if (stat(cont->path, &sb) < 0) {
			if (errno != ENOENT) {
				exists = false;
			} else {
				perror("stat");
				return false;
			}
		} else {
			exists = true;
		}
	} else if (exists) {
		/* Just exists, not a symlink */
		++ask;
	}

	if (pg->force_level < ask) {
		hxmc_t *tmp = NULL;

		if (!pg->interactive) {
			printf("Not automatically overwriting file.\n");
			return false;
		}

		printf("Do you really want to overwrite %s? (y/n)\n",
		       cont->path);
		if (HX_getl(&tmp, stdin) == NULL)
			return false;
		if (HX_tolower(*tmp) != 'y')
			return false;
		HXmc_free(tmp);
	}

	return true;
}

static bool ehd_xfer(int fd, size_t z)
{
#define BUFSIZE (65536 / sizeof(*buffer) * sizeof(*buffer))
	unsigned int i;
	bool ret = true;
	int *buffer;
	ssize_t wret;

	buffer = malloc(BUFSIZE);
	if (buffer == NULL) {
		perror("malloc");
		return false;
	}

	printf("Writing random data to container\n");
	for (i = 0; i < BUFSIZE / sizeof(*buffer); ++i)
		buffer[i] = HX_rand();

	while (z > 0) {
		wret = write(fd, buffer, (z >= BUFSIZE) ? BUFSIZE : z);
		if (wret < 0) {
			perror("write");
			ret = false;
			break;
		}
		z -= wret;
		if ((z & 0xffffff) == 0) {
			printf("\r\e[2K%zu MB left", z >> 20);
			fflush(stdout);
		}
	}
	printf("\n");
	free(buffer);
	return ret;
#undef BUFSIZE
}

static bool ehd_xfer2(const char *name, size_t size)
{
	bool ret;
	int fd;

	fd = open(name, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", name, strerror(errno));
		return false;
	}
	ret = ehd_xfer(fd, size);
	close(fd);
	return ret;
}

static bool ehd_create_container(struct ehd_ctl *pg)
{
	struct container_ctl *cont = &pg->cont;
	bool ret = false;
	int fd = -1;

	fd = open(cont->path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", cont->path, strerror(errno));
		return false;
	}
	if (cont->skip_random) {
		printf("Truncating container\n");
		if (!cont->blkdev) {
			/*
			 * /dev nodes should not be owned by user, even if it
			 * is "their" voulme. Note that due to /dev being on
			 * tmpfs, ownership is lost anyway after a reboot or
			 * device removal/add.
			 */
			if (fchown(fd, cont->uid, -1) < 0) {
				perror("fchown");
				goto out;
			}
			/*
			 * Truncate on block devices does not make sense and
			 * would also return EINVAL. So do not do it for block
			 * devices either.
			 */
			if (ftruncate(fd, cont->size) < 0) {
				perror("ftruncate");
				goto out;
			}
		}
	} else {
		ehd_xfer(fd, cont->size);
	}
	ret = true;
 out:
	if (fd >= 0)
		close(fd);
	return ret;
}

static bool ehd_mkfs(struct ehd_mount_request *rq,
    struct ehd_mount_info *mtinfo, void *priv)
{
	const struct ehd_ctl *pg = priv;
	const struct container_ctl *cont = &pg->cont;
	const char *crypto_device = NULL;
	int ret;

	ehd_mtinfo_get(mtinfo, EHD_MTINFO_CRYPTODEV, &crypto_device);
	if (!cont->skip_random)
		ehd_xfer2(crypto_device, cont->size);

	hxmc_t *fsprog = HXmc_strinit("mkfs.");
	HXmc_strcat(&fsprog, cont->fstype);
	const char *const argv[] = {fsprog, crypto_device, NULL};

	fprintf(stderr, "-- Calling %s %s\n", fsprog, crypto_device);
	if ((ret = HXproc_run_sync(argv, HXPROC_VERBOSE)) < 0 || ret != 0)
		fprintf(stderr, "%s failed with run_sync status %d\n",
		        fsprog, ret);

	HXmc_free(fsprog);
	return ret == 0;
}

static void ehd_parse_name(const char *s, char *cipher, size_t cipher_size,
    char *cipher_mode, size_t cm_size)
{
	const char *p;

	p = strchr(s, '-');
	if (p == NULL)
		p = s + strlen(s);
	*cipher = '\0';
	HX_strlncat(cipher, s, cipher_size, p - s);
	if (p == NULL || *p != '-')
		return;
	++p;
	HX_strlcpy(cipher_mode, p, cm_size);
}

static int ehd_init_volume_luks(struct ehd_mount_request *rq,
    struct ehd_mount_info *mtinfo, void *priv)
{
	/*
	 * Pick what? WP specifies that XTS has a wider support range than
	 * ESSIV. But XTS is also double complexity due to the double key,
	 * without adding anything of value.
	 */
	struct ehd_ctl *pg = priv;
	struct container_ctl *cont = &pg->cont;
	char cipher[32], cipher_mode[32];
	struct crypt_params_luks1 format_params = {.hash = cont->hash};
	struct crypt_device *cd = NULL;
	const char *lower_dev = NULL;
	int ret;

	BUILD_BUG_ON(!__builtin_types_compatible_p(
		__typeof__(&ehd_init_volume_luks), ehd_hook_fn_t));

	ehd_parse_name(cont->cipher, cipher, sizeof(cipher),
	               cipher_mode, sizeof(cipher_mode));
	ret = ehd_mtinfo_get(mtinfo, EHD_MTINFO_LOWERDEV, &lower_dev);
	if (ret <= 0 || lower_dev == NULL)
		goto out;
	ret = crypt_init(&cd, lower_dev);
	if (ret < 0) {
		fprintf(stderr, "crypt_init: %s: %s\n",
		        lower_dev, strerror(-ret));
		goto out;
	}
	ret = crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, NULL,
	      (cont->keybits + CHAR_BIT - 1) / CHAR_BIT, &format_params);
	if (ret < 0) {
		fprintf(stderr, "crypt_format: %s\n", strerror(-ret));
		goto out2;
	}
	ret = crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT, NULL, 0,
	      pg->password, strlen(pg->password));
	if (ret < 0) {
		fprintf(stderr, "add_by_volume_key: %s\n", strerror(-ret));
		goto out2;
	}
	ret = 1;
 out2:
	crypt_free(cd);
 out:
	return ret;
}

/**
 * ehd_init_volume - set up loop device association if necessary
 */
static bool ehd_init_volume(struct ehd_ctl *pg)
{
	struct container_ctl *cont = &pg->cont;
	struct ehd_mount_info *mount_info;
	struct ehd_mount_request *mount_request;
	int ret;

	mount_request = ehd_mtreq_new();
	if (mount_request == NULL)
		return -errno;
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_CONTAINER, cont->path);
	if (ret < 0)
		goto out;
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_KEY_SIZE,
	                    strlen(pg->password));
	if (ret < 0)
		goto out;
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_KEY_DATA, pg->password);
	if (ret < 0)
		goto out;
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_READONLY, EHD_LOSETUP_RW);
	if (ret < 0)
		goto out;
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_LOOP_HOOK,
	                    ehd_init_volume_luks);
	if (ret < 0)
		goto out;
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_HOOK_PRIV, pg);
	if (ret < 0)
		goto out;
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_CRYPTO_HOOK, ehd_mkfs);
	if (ret < 0)
		goto out;
	/* We don't need to mount it */
	ret = ehd_mtreq_set(mount_request, EHD_MTREQ_LAST_STAGE,
	                    EHD_MTREQ_STAGE_CRYPTO);
	if (ret < 0)
		goto out;

	ret = ehd_load(mount_request, &mount_info);
	if (ret > 0) {
		ret = ehd_unload(mount_info);
		ehd_mtinfo_free(mount_info);
	}
 out:
	ehd_mtreq_free(mount_request);
	return ret > 0;
}

static void ehd_final_printout(const struct ehd_ctl *pg)
{
	printf(
		"-- (The important parts of) the new entry:\n\n"
		"<volume fstype=\"crypt\" path=\"%s\" "
		"mountpoint=\"REPLACEME\" />\n\n"
		"-- Substitute paths by absolute ones.\n\n",
		pg->cont.path);
}

/**
 * ehd_fill_options_container - complete container control block
 */
static bool ehd_fill_options_container(struct ehd_ctl *pg)
{
#define DEFAULT_FSTYPE "ext4"
	struct container_ctl *cont = &pg->cont;
	hxmc_t *tmp = HXmc_meminit(NULL, 0);
	int ret = false;
	struct stat sb;

	if (cont->user == NULL) {
		cont->uid = -1;
	} else {
		struct passwd *p;
		if ((p = getpwnam(cont->user)) == NULL) {
			fprintf(stderr, "Cannot resolve user %s\n", cont->user);
			goto out;
		}
		cont->uid = p->pw_uid;
	}

	if (cont->fstype == NULL)
		cont->fstype = xstrdup(DEFAULT_FSTYPE);

	if (cont->path == NULL) {
		if (!pg->interactive) {
			fprintf(stderr, "You must specify the path (file "
			        "location) to store container at, using the "
				"-f option\n");
			goto out;
		}
		*tmp = '\0';
		do {
			printf("Container path: ");
			fflush(stdout);
			HX_getl(&tmp, stdin);
			HX_chomp(tmp);
		} while (*tmp == '\0');
		cont->path = HX_strdup(tmp);
	}

	if (stat(cont->path, &sb) < 0) {
		if (errno != ENOENT) {
			fprintf(stderr, "stat %s: %s\n",
			        cont->path, strerror(errno));
			return false;
		}
	} else if (S_ISBLK(sb.st_mode)) {
		cont->blkdev = true;
		if (cont->size == 0) {
			cont->size = pmt_block_getsize64(cont->path);
			if (cont->size != 0)
				printf("Size of device: %llu MB\n",
				       cont->size >> 20);
		}
	}

	if (cont->size == 0) {
		unsigned int s;

		if (!pg->interactive) {
			fprintf(stderr, "You must specify a non-zero "
			        "container size using -s\n");
			goto out;
		}
		do {
			printf("Container size in megabytes: ");
			fflush(stdout);
			HX_getl(&tmp, stdin);
			HX_chomp(tmp);
			s = strtoul(tmp, NULL, 0);
			s <<= 20; /* megabytes -> bytes */
		} while (*tmp == '\0' || s == 0);
		cont->size = s;
	}

	if (strcmp(cont->fstype, "xfs") == 0 && cont->size < 16*1048576)
		fprintf(stderr, "Warning: XFS volumes need to be "
		        "at least 16 MB\n");

	if (cont->cipher == NULL) {
		cont->cipher = HX_strdup(ehd_default_dmcipher);
		if (cont->keybits == 0)
			cont->keybits = ehd_default_strength;
	} else if (cont->keybits == 0) {
		fprintf(stderr, "You have chosen the cipher %s, but did not "
		        "specify a key size. Assuming 256 bits. This may fail "
		        "if the cipher does not support that keysize.\n",
		        cont->cipher);
		cont->keybits = ehd_default_strength;
	}
	if (cont->hash == NULL)
		cont->hash = HX_strdup(ehd_default_hash);

	ret = ehd_cipherdigest_security(cont->cipher);
	if (ret < 0)
		fprintf(stderr, "pmt_cipherdigest_security: %s\n", strerror(-ret));
	else if (ret < EHD_SECURITY_UNSPEC)
		fprintf(stderr, "Cipher \"%s\" is considered insecure.\n",
		        cont->cipher);
	ret = ehd_cipherdigest_security(cont->hash);
	if (ret < 0)
		fprintf(stderr, "pmt_cipherdigest_security: %s\n", strerror(-ret));
	else if (ret < EHD_SECURITY_UNSPEC)
		fprintf(stderr, "Hash \"%s\" is considered insecure.\n",
		        cont->hash);

	ret = true;
 out:
	HXmc_free(tmp);
	return ret;
}

static bool ehd_get_options(int *argc, const char ***argv, struct ehd_ctl *pg)
{
	struct container_ctl *cont = &pg->cont;
	struct HXoption options_table[] = {
		{.sh = 'D', .type = HXTYPE_NONE, .ptr = &ehd_debug,
		 .help = "Enable debugging"},
		{.sh = 'F', .type = HXTYPE_NONE | HXOPT_INC,
		 .ptr = &pg->force_level,
		 .help = "Force operation (also -FF)"},
		{.sh = 'c', .type = HXTYPE_STRING, .ptr = &cont->cipher,
		 .help = "Name of cipher to be used for filesystem (cryptsetup name)",
		 .htyp = "NAME"},
		{.sh = 'f', .type = HXTYPE_STRING, .ptr = &cont->path,
		 .help = "Path of the new container", .htyp = "FILE/BDEV"},
		{.sh = 'h', .type = HXTYPE_STRING, .ptr = &cont->hash,
		 .help = "Name of hash to be used for master keys (cryptsetup name)",
		 .htyp = "NAME"},
		{.sh = 'k', .type = HXTYPE_UINT, .ptr = &cont->keybits,
		 .help = "Number of bits fscipher (-c) operates with",
		 .htyp = "BITS"},
		{.sh = 's', .type = HXTYPE_ULLONG, .ptr = &cont->size,
		 .help = "Container size in megabytes"},
		{.sh = 't', .type = HXTYPE_STRING, .ptr = &cont->fstype,
		 .help = "Filesystem type (default: " DEFAULT_FSTYPE ")",
		 .htyp = "NAME"},
		{.sh = 'u', .type = HXTYPE_STRING, .ptr = &cont->user,
		 .help = "Name of the user to create volume for",
		 .htyp = "USER"},
		{.sh = 'x', .type = HXTYPE_NONE, .ptr = &cont->skip_random,
		 .help = "Do not fill container with random data"},
		HXOPT_AUTOHELP,
		HXOPT_TABLEEND,
	};

	if (HX_getopt(options_table, argc, argv, HXOPT_USAGEONERR) !=
	    HXOPT_ERR_SUCCESS)
		return false;

	cont->size <<= 20; /* mb -> b */
	pg->interactive = isatty(fileno(stdin));
	return ehd_fill_options_container(pg);
}

static int main2(int argc, const char **argv, struct ehd_ctl *pg)
{
	hxmc_t *password, *password2;
	int ret;

	ehd_logctl(EHD_LOGFT_NOSYSLOG, EHD_LOG_SET);
	if (!ehd_get_options(&argc, &argv, pg))
		return EXIT_FAILURE;

	if (!ehd_check(pg))
		return EXIT_FAILURE;
	if (!ehd_create_container(pg))
		return EXIT_FAILURE;
	printf("NOTE: Use the end-user passphrase here. DO NOT feed it a hash "
	       "of a passphrase or anything otherwise fancy. pmt-ehd(8), as "
	       "well as cryptsetup(8)'s luksFormat will, by default, do the "
	       "master key generation and hashing themselves!\n");
	password  = ehd_get_password(NULL);
	password2 = ehd_get_password("Reenter password: ");
	if (password == NULL || password2 == NULL ||
	    strcmp(password, password2) != 0) {
		fprintf(stderr, "Passwords mismatch.\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	pg->password = (password != NULL) ? password : "";
	ret = ehd_init_volume(pg) ? EXIT_SUCCESS : EXIT_FAILURE;
	if (ret == EXIT_SUCCESS)
		ehd_final_printout(pg);

 out:
	if (password != NULL) {
		memset(password, '\0', HXmc_length(password));
		HXmc_free(password);
	}
	if (password2 != NULL) {
		memset(password2, '\0', HXmc_length(password2));
		HXmc_free(password2);
	}
	return ret;
}

int main(int argc, const char **argv)
{
	struct ehd_ctl pg;
	int ret;

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

	memset(&pg, 0, sizeof(pg));
	ret = main2(argc, argv, &pg);
	cryptmount_exit();
	HX_exit();
	return ret;
}
