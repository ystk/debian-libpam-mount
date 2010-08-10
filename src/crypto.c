/*
 *	Copyright © Jan Engelhardt, 2008
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include "config.h"
#include "pam_mount.h"
#ifdef HAVE_LIBCRYPTO
#	include <openssl/evp.h>
#endif

/**
 * ehd_mtfree - free data associated with an EHD mount info block
 */
void ehd_mtfree(struct ehd_mount *mt)
{
	free(mt->container);
	HXmc_free(mt->crypto_device);
	HXmc_free(mt->crypto_name);
	if (mt->loop_device != NULL) {
		pmt_loop_release(mt->lower_device);
		free(mt->loop_device);
	}
}

/**
 * ehd_load - set up crypto device for an EHD container
 * @cont_path:		path to the container
 * @crypto_device:	store crypto device here
 * @cipher:		filesystem cipher
 * @hash:		hash function for cryptsetup (default: plain)
 * @fskey:		unencrypted fskey data (not path)
 * @fskey_size:		size of @fskey, in bytes
 * @readonly:		set up loop device as readonly
 */
int ehd_load(const struct ehd_mtreq *req, struct ehd_mount *mt)
{
	struct stat sb;
	int saved_errno, ret;

	memset(mt, 0, sizeof(*mt));
	if (stat(req->container, &sb) < 0) {
		l0g("Could not stat %s: %s\n", req->container, strerror(errno));
		return -errno;
	}

	if ((mt->container = HX_strdup(req->container)) == NULL)
		goto out_err;
	if (S_ISBLK(sb.st_mode)) {
		mt->loop_device  = NULL;
		mt->lower_device = req->container;
	} else {
		/* need losetup since cryptsetup needs block device */
		w4rn("Setting up loop device for file %s\n", req->container);
		ret = pmt_loop_setup(req->container, &mt->loop_device,
		      req->readonly);
		if (ret == 0) {
			l0g("Error: no free loop devices\n");
			goto out_ser;
		} else if (ret < 0) {
			l0g("Error setting up loopback device for %s: %s\n",
			    req->container, strerror(-ret));
			goto out_ser;
		} else {
			w4rn("Using %s\n", mt->loop_device);
			mt->lower_device = mt->loop_device;
		}
	}

#ifdef HAVE_LIBCRYPTSETUP
	ret = ehd_dmcrypt_ops.load(req, mt);
#elif defined(HAVE_DEV_CGDVAR_H)
	ret = ehd_cgd_ops.load(req, mt);
#else
	ret = -EOPNOTSUPP;
#endif
	if (ret <= 0)
		goto out_ser;

	return ret;

 out_err:
	ret = -errno;
 out_ser:
	saved_errno = errno;
	ehd_mtfree(mt);
	errno = saved_errno;
	return ret;
}

/**
 * ehd_unload - unload EHD image
 * @crypto_device:	dm-crypt device (/dev/mapper/X)
 * @only_crypto:	do not unload any lower device
 *
 * Determines the underlying device of the crypto target. Unloads the crypto
 * device, and then the loop device if one is used.
 *
 * Using the external cryptsetup program because the cryptsetup C API does
 * not look as easy as the loop one, and does not look shared (i.e. available
 * as a system library) either.
 */
int ehd_unload(const struct ehd_mount *mt)
{
	int ret;

#ifdef HAVE_LIBCRYPTSETUP
	ret = ehd_dmcrypt_ops.unload(mt);
#elif defined(HAVE_DEV_CGDVAR_H)
	ret = ehd_cgd_ops.unload(mt);
#else
	ret = -EOPNOTSUPP;
#endif

	/* Try to free loop device even if cryptsetup remove failed */
	if (mt->loop_device != NULL)
		ret = pmt_loop_release(mt->loop_device);

	return ret;
}

#ifdef HAVE_LIBCRYPTO
struct decrypt_info {
	const char *keyfile;
	hxmc_t *password;
	const EVP_CIPHER *cipher;
	const EVP_MD *digest;

	const unsigned char *data;
	unsigned int keysize;

	const unsigned char *salt;
};

static hxmc_t *ehd_decrypt_key2(const struct decrypt_info *info)
{
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	unsigned int out_cumul_len = 0;
	EVP_CIPHER_CTX ctx;
	int out_len = 0;
	hxmc_t *out;

	if (EVP_BytesToKey(info->cipher, info->digest, info->salt,
	    signed_cast(const unsigned char *, info->password),
	    (info->password == NULL) ? 0 : HXmc_length(info->password),
	    1, key, iv) <= 0) {
		l0g("EVP_BytesToKey failed\n");
		return false;
	}

	out = HXmc_meminit(NULL, info->keysize + info->cipher->block_size);
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, info->cipher, NULL, key, iv);
	EVP_DecryptUpdate(&ctx, signed_cast(unsigned char *,
		&out[out_len]), &out_len, info->data, info->keysize);
	out_cumul_len += out_len;
	EVP_DecryptFinal_ex(&ctx, signed_cast(unsigned char *,
		&out[out_len]), &out_len);
	out_cumul_len += out_len;
	HXmc_setlen(&out, out_cumul_len);
	EVP_CIPHER_CTX_cleanup(&ctx);

	return out;
}

hxmc_t *ehd_decrypt_key(const char *keyfile, const char *digest_name,
    const char *cipher_name, hxmc_t *password)
{
	struct decrypt_info info = {
		.keyfile  = keyfile,
		.digest   = EVP_get_digestbyname(digest_name),
		.cipher   = EVP_get_cipherbyname(cipher_name),
		.password = password,
	};
	hxmc_t *f_ret = NULL;
	unsigned char *buf;
	struct stat sb;
	ssize_t i_ret;
	int fd;

	if (info.digest == NULL) {
		l0g("Unknown digest: %s\n", digest_name);
		return false;
	}
	if (info.cipher == NULL) {
		l0g("Unknown cipher: %s\n", cipher_name);
		return false;
	}
	if ((fd = open(info.keyfile, O_RDONLY)) < 0) {
		l0g("Could not open %s: %s\n", info.keyfile, strerror(errno));
		return false;
	}
	if (fstat(fd, &sb) < 0) {
		l0g("stat: %s\n", strerror(errno));
		goto out;
	}

	if ((buf = xmalloc(sb.st_size)) == NULL)
		return false;

	if ((i_ret = read(fd, buf, sb.st_size)) != sb.st_size) {
		l0g("Incomplete read of %u bytes got %Zd bytes\n",
		    sb.st_size, i_ret);
		goto out2;
	}

	info.salt    = &buf[strlen("Salted__")];
	info.data    = info.salt + PKCS5_SALT_LEN;
	info.keysize = sb.st_size - (info.data - buf);
	f_ret = ehd_decrypt_key2(&info);

 out2:
	free(buf);
 out:
	close(fd);
	return f_ret;
}
#endif /* HAVE_LIBCRYPTO */

static unsigned int __cipher_digest_security(const char *s)
{
	static const char *const blacklist[] = {
		"ecb",
		"rc2", "rc4", "des", "des3",
		"md2", "md4",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(blacklist); ++i)
		if (strcmp(s, blacklist[i]) == 0)
			return 0;

	return 2;
}

/**
 * cipher_digest_security - returns the secure level of a cipher/digest
 * @s:	name of the cipher or digest specification
 * 	(can either be OpenSSL or cryptsetup name)
 *
 * Returns 0 if it is considered insecure, 1 if I would have a bad feeling
 * using it, and 2 if it is appropriate.
 */
unsigned int cipher_digest_security(const char *s)
{
	char *base, *tmp, *wp;
	unsigned int ret;

	if ((base = xstrdup(s)) == NULL)
		return 2;

	tmp = base;
	while ((wp = HX_strsep(&tmp, ",-.:_")) != NULL)
		if ((ret = __cipher_digest_security(wp)) < 2)
			break;

	free(base);
	return ret;
}

static struct {
	struct sigaction oldact;
	bool echo;
	int fd;
} pmt_pwq_restore;

static void pmt_password_stop(int s)
{
	struct termios ti;

	if (!pmt_pwq_restore.echo)
		return;
	if (tcgetattr(pmt_pwq_restore.fd, &ti) == 0) {
		ti.c_lflag |= ECHO;
		tcsetattr(pmt_pwq_restore.fd, TCSANOW, &ti);
	}
	sigaction(s, &pmt_pwq_restore.oldact, NULL);
	if (s != 0)
		kill(0, s);
}

static hxmc_t *__pmt_get_password(FILE *fp)
{
	hxmc_t *ret = NULL;
	memset(&pmt_pwq_restore, 0, sizeof(pmt_pwq_restore));
	pmt_pwq_restore.fd = fileno(fp);

	if (isatty(fileno(fp))) {
		struct sigaction sa;
		struct termios ti;

		if (tcgetattr(fileno(fp), &ti) == 0) {
			pmt_pwq_restore.echo = ti.c_lflag & ECHO;
			if (pmt_pwq_restore.echo) {
				sigemptyset(&sa.sa_mask);
				sa.sa_handler = pmt_password_stop;
				sa.sa_flags   = SA_RESETHAND;
				sigaction(SIGINT, &sa, NULL);
				ti.c_lflag &= ~ECHO;
				tcsetattr(fileno(fp), TCSANOW, &ti);
				tcflush(fileno(fp), TCIFLUSH);
			}
		}
	}

	if (HX_getl(&ret, fp) != NULL) {
		HX_chomp(ret);
		HXmc_setlen(&ret, strlen(ret));
	}
	pmt_password_stop(0);
	return ret;
}

hxmc_t *pmt_get_password(const char *prompt)
{
	hxmc_t *ret;

	printf("%s", (prompt != NULL) ? prompt : "Password: ");
	fflush(stdout);
	ret = __pmt_get_password(stdin);
	printf("\n");
	return ret;
}
