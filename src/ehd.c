/*
 *	Encrypted Home Disk manipulation utility
 *	Copyright © Jan Engelhardt, 2008
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
#include <libHX/misc.h>
#include <libHX/option.h>
#include <libHX/proc.h>
#include <libHX/string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <security/pam_appl.h>
#include <pwd.h>
#include "pam_mount.h"

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
	char *path, *fstype, *cipher, *user;
	unsigned int keybits, skip_random, uid;
	bool blkdev;
};

/**
 * struct fskey_ctl - fskey generation control block
 * @path:	read/write fskey at this path
 * @cipher:	cipher name specification as understood by OpenSSL
 * @digest:	digest name specification as understood by OpenSSL
 */
struct fskey_ctl {
	char *path, *cipher, *digest;
};

/**
 * struct ehd_ctl - program control block
 * @force_level:	number of "-f"s passed
 * @interactive:	if stdin is a tty
 * @cont:		container control substructure
 * @fskey:		fskey control substructure
 */
struct ehd_ctl {
	unsigned int force_level;
	struct container_ctl cont;
	struct fskey_ctl fskey;
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
		char target[256];
		unsigned int i = sizeof(target);

		/* Get confirmation for overwriting files */
		++ask;
		memset(target, 0, i);
		ret = readlink(cont->path, target, sizeof(target));
		if (ret < 0) {
			fprintf(stderr, "readlink %s: %s\n",
			        cont->path, strerror(errno));
			return false;
		}
		--i;
		if (target[i] != '\0' && i >= 16) {
			target[i--] = '\0';
			target[i--] = '.';
			target[i--] = '.';
			target[i--] = '.';
		} else {
			target[i--] = '\0';
		}

		printf("%s is a symlink and points to %s\n",
		       cont->path, target);
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
	/*
	 * Kill off any potential LUKS header, otherwise ehd_load, which will
	 * be called later, misidentifies our (new) PLAIN volume.
	 */
	lseek(fd, 0, SEEK_SET);
	if (write(fd, "\0\0\0\0", 4) != 4)
		fprintf(stderr, "write: %s\n", strerror(errno));
	ret = true;
 out:
	if (fd >= 0)
		close(fd);
	return ret;
}

/**
 * ehd_create_fskey - create encrypted fskey file
 * @password:		Password to encrypt the fskey with
 * @fskey:		Raw fskey (unencrypted)
 */
static bool ehd_create_fskey(struct ehd_ctl *pg, const char *password,
    const unsigned char *fskey, unsigned int fskey_size)
{
	const struct container_ctl *cont = &pg->cont;
	const struct fskey_ctl *fsk = &pg->fskey;
	unsigned char salt[PKCS5_SALT_LEN], key[EVP_MAX_KEY_LENGTH];
	unsigned char iv[EVP_MAX_IV_LENGTH];
	const EVP_CIPHER *cipher;
	const EVP_MD *digest;
	EVP_CIPHER_CTX ctx;
	int out_len, out_cumul_len, fd;
	hxmc_t *out;
	bool ret = false;

	digest = EVP_get_digestbyname(fsk->digest);
	if (digest == NULL) {
		fprintf(stderr, "Unknown digest: %s\n", fsk->digest);
		return false;
	}

	cipher = EVP_get_cipherbyname(fsk->cipher);
	if (cipher == NULL) {
		fprintf(stderr, "Unknown cipher: %s\n", fsk->cipher);
		return false;
	}

	printf("Using openssl cipher \"%s\" and hash \"%s\"\n",
	       fsk->cipher, fsk->digest);

	/* Make some salt */
	RAND_bytes(salt, sizeof(salt));
	out = HXmc_meminit(NULL, strlen("Salted__") + sizeof(salt) +
	      fskey_size + cipher->block_size);
	HXmc_strcpy(&out, "Salted__");
	HXmc_memcat(&out, salt, sizeof(salt));
	out_cumul_len = HXmc_length(out);

	/* Then pepper */
	EVP_BytesToKey(cipher, digest, salt,
	               signed_cast(const unsigned char *, password),
	               strlen(password), 1, key, iv);

	/* And hex salad */
	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, cipher, NULL, key, iv);
	EVP_EncryptUpdate(&ctx, signed_cast(unsigned char *,
	                  &out[out_cumul_len]), &out_len, fskey, fskey_size);
	out_cumul_len += out_len;
	EVP_EncryptFinal_ex(&ctx, signed_cast(unsigned char *,
	                    &out[out_cumul_len]), &out_len);
	out_cumul_len += out_len;
	EVP_CIPHER_CTX_cleanup(&ctx);

	if ((fd = open(fsk->path, O_WRONLY | O_TRUNC | O_CREAT,
	    S_IRUSR | S_IWUSR)) < 0) {
		fprintf(stderr, "Could not open %s: %s\n",
		        fsk->path, strerror(errno));
		goto out;
	}
	if (fchown(fd, cont->uid, -1) < 0) {
		perror("fchown");
		goto out;
	}
	if (write(fd, out, out_cumul_len) != out_cumul_len) {
		perror("write");
		goto out;
	}
	ret = true;
 out:
	close(fd);
	HXmc_free(out);
	return ret;
}

static bool ehd_mkfs(const struct ehd_ctl *pg, const hxmc_t *crypto_device)
{
	const struct container_ctl *cont = &pg->cont;

	hxmc_t *fsprog = HXmc_strinit("mkfs.");
	HXmc_strcat(&fsprog, cont->fstype);
	const char *const argv[] = {fsprog, crypto_device, NULL};
	int ret;

	fprintf(stderr, "-- Calling %s\n", fsprog);
	if ((ret = HXproc_run_sync(argv, HXPROC_VERBOSE)) < 0 || ret != 0)
		fprintf(stderr, "%s failed with run_sync status %d\n",
		        fsprog, ret);

	HXmc_free(fsprog);
	return ret == 0;
}

/**
 * ehd_init_volume - set up loop device association if necessary
 */
static bool ehd_init_volume(struct ehd_ctl *pg, const char *password)
{
	struct container_ctl *cont = &pg->cont;
	hxmc_t *fskey;
	struct ehd_mount mount_info;
	struct ehd_mtreq mount_request = {
		.container = cont->path,
		.fs_cipher = cont->cipher,
		/*
		 * "plain" because pmt-ehd generates mathematically perfect
		 * fskeys itself and further hashing would only reduce the
		 * strength for the fskeys we generate.
		 */
		.fs_hash   = "plain",
		.readonly  = false,
	};
	bool f_ret = false;
	int ret;

	mount_request.key_size = (cont->keybits + CHAR_BIT - 1) / CHAR_BIT;
	fskey = HXmc_meminit(NULL, mount_request.key_size);
	if (fskey == NULL) {
		perror("HXmc_meminit");
		abort();
	}

	RAND_bytes(signed_cast(unsigned char *, fskey), mount_request.key_size);
	mount_request.trunc_keysize = mount_request.key_size;
	mount_request.key_data = fskey;
	f_ret = false;
	if (ehd_create_fskey(pg, password, mount_request.key_data,
	    mount_request.key_size) &&
	    ehd_load(&mount_request, &mount_info) > 0) {
		if (!cont->skip_random)
			ehd_xfer2(mount_info.crypto_device, cont->size);
		f_ret = ehd_mkfs(pg, mount_info.crypto_device);
		ret   = ehd_unload(&mount_info);
		/* If mkfs failed, use its code. */
		if (f_ret)
			f_ret = ret > 0;
	}

	HXmc_free(fskey);
	mount_request.key_data = NULL;
	return f_ret;
}

static void ehd_final_printout(const struct ehd_ctl *pg)
{
	printf(
		"-- The (important parts) of the new entry:\n\n"
		"<volume fstype=\"crypt\" path=\"%s\" "
		"mountpoint=\"REPLACEME\" cipher=\"%s\" "
		"fskeycipher=\"%s\" fskeyhash=\"%s\" "
		"fskeypath=\"%s\" />\n\n"
		"-- Substitute paths by absolute ones.\n\n",
		pg->cont.path, pg->cont.cipher, pg->fskey.cipher,
		pg->fskey.digest, pg->fskey.path);
}

#ifdef HAVE_LINUX_FS_H
	/* elsewhere */
#else
size_t pmt_block_getsize64(const char *path)
{
	fprintf(stderr, "%s: pam_mount does not know how to retrieve the "
	        "size of a block device on this platform.\n", __func__);
	return 0;
}
#endif

/**
 * ehd_fill_options_container - complete container control block
 */
static bool ehd_fill_options_container(struct ehd_ctl *pg)
{
#define DEFAULT_FSTYPE "ext4"
	struct container_ctl *cont = &pg->cont;
	hxmc_t *tmp = HXmc_meminit(NULL, 0);
	bool ret = false;
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
		} while (*tmp == '\0' || s == 0);
		cont->size = s;
	}

	if (strcmp(cont->fstype, "xfs") == 0 && cont->size < 16)
		fprintf(stderr, "Warning: XFS volumes need to be "
		        "at least 16 MB\n");

	cont->size <<= 20; /* megabytes -> bytes */

	if (cont->cipher == NULL) {
		cont->cipher = HX_strdup(PMT_DFL_DMCRYPT_CIPHER);
		if (cont->keybits == 0)
			cont->keybits = 256;
	} else if (cont->keybits == 0) {
		fprintf(stderr, "You have chosen the cipher %s, but did not "
		        "specify a key size. Assuming 256 bits. This may fail "
		        "if the cipher does not support that keysize.\n",
		        cont->cipher);
		cont->keybits = 256;
	}

	if (cipher_digest_security(cont->cipher) < 1) {
		fprintf(stderr, "Cipher \"%s\" is considered insecure.\n",
		        cont->cipher);
//		return false;
	}

	ret = true;
 out:
	HXmc_free(tmp);
	return ret;
}

static bool ehd_fill_options_fskey(struct ehd_ctl *pg)
{
	struct fskey_ctl *fsk = &pg->fskey;
	hxmc_t *tmp = HXmc_meminit(NULL, 0);
	bool ret = false;

	if (fsk->path == NULL) {
		if (!pg->interactive) {
			fprintf(stderr, "You must specify the path to store "
			        "the filesystem key at, using the -p option\n");
			goto out;
		}
		*tmp = '\0';
		do {
			printf("Filesystem key location: ");
			fflush(stdout);
			HX_getl(&tmp, stdin);
			HX_chomp(tmp);
		} while (*tmp == '\0');
		fsk->path = HX_strdup(tmp);
	}

	if (fsk->cipher == NULL)
		fsk->cipher = HX_strdup(PMT_DFL_FSK_CIPHER);
	if (fsk->digest == NULL)
		fsk->digest = HX_strdup(PMT_DFL_FSK_HASH);

	if (cipher_digest_security(fsk->cipher) < 1) {
		fprintf(stderr, "Cipher \"%s\" is considered insecure.\n",
		        fsk->cipher);
//		return false;
	} else if (cipher_digest_security(fsk->digest) < 1) {
		fprintf(stderr, "Digest \"%s\" is considered insecure.\n",
		        fsk->digest);
//		return false;
	}

	ret = true;
 out:
	HXmc_free(tmp);
	return ret;
}

static bool ehd_get_options(int *argc, const char ***argv, struct ehd_ctl *pg)
{
	struct container_ctl *cont = &pg->cont;
	struct fskey_ctl *fsk = &pg->fskey;
	struct HXoption options_table[] = {
		{.sh = 'D', .type = HXTYPE_NONE, .ptr = &Debug,
		 .help = "Enable debugging"},
		{.sh = 'F', .type = HXTYPE_NONE | HXOPT_INC,
		 .ptr = &pg->force_level,
		 .help = "Force operation (also -FF)"},
		{.sh = 'c', .type = HXTYPE_STRING, .ptr = &cont->cipher,
		 .help = "Name of cipher to be used for filesystem (cryptsetup name)",
		 .htyp = "NAME"},
		{.sh = 'f', .type = HXTYPE_STRING, .ptr = &cont->path,
		 .help = "Path of the new container", .htyp = "FILE/BDEV"},
		{.sh = 'h', .type = HXTYPE_STRING, .ptr = &fsk->digest,
		 .help = "Digest for key generation (OpenSSL name)",
		 .htyp = "NAME"},
		{.sh = 'i', .type = HXTYPE_STRING, .ptr = &fsk->cipher,
		 .help = "Filesystem key cipher (OpenSSL name)",
		 .htyp = "NAME"},
		{.sh = 'k', .type = HXTYPE_UINT, .ptr = &cont->keybits,
		 .help = "Number of bits fscipher (-c) operates with",
		 .htyp = "BITS"},
		{.sh = 'p', .type = HXTYPE_STRING, .ptr = &fsk->path,
		 .help = "Filesystem key location", .htyp = "FILE"},
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

	if (HX_getopt(options_table, argc, argv, HXOPT_USAGEONERR) <= 0)
		return false;

	pg->interactive = isatty(fileno(stdin));
	return ehd_fill_options_container(pg) && ehd_fill_options_fskey(pg);
}

static int main2(int argc, const char **argv, struct ehd_ctl *pg)
{
	hxmc_t *password, *password2;
	int ret;

	if (!ehd_get_options(&argc, &argv, pg))
		return EXIT_FAILURE;

	pmtlog_path[PMTLOG_ERR][PMTLOG_STDERR] = true;
	pmtlog_path[PMTLOG_DBG][PMTLOG_STDERR] = Debug;
	pmtlog_prefix = "ehd";

	if (!ehd_check(pg))
		return EXIT_FAILURE;
	if (!ehd_create_container(pg))
		return EXIT_FAILURE;
	password  = pmt_get_password(NULL);
	password2 = pmt_get_password("Reenter password: ");
	if (password == NULL || password2 == NULL ||
	    strcmp(password, password2) != 0) {
		fprintf(stderr, "Passwords mismatch.\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	ret = ehd_init_volume(pg, password != NULL ? password : "") ?
	      EXIT_SUCCESS : EXIT_FAILURE;
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

	Debug = false;
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	memset(&pg, 0, sizeof(pg));

	return main2(argc, argv, &pg);
}
