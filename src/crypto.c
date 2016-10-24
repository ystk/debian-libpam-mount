/*
 *	Copyright Jan Engelhardt, 2008-2011
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
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/init.h>
#include <libHX/string.h>
#include "config.h"
#include "cmt-internal.h"
#include "libcryptmount.h"
#include "pam_mount.h"
#ifdef HAVE_LIBCRYPTO
#	include <openssl/evp.h>
#endif

/**
 * struct ehd_keydec_request - parameter agglomerator for ehd_kdreq_final
 * @keyfile:	path to the key file
 * @digest:	digest used for the key file
 * @cipher:	cipher used for the key file
 * @password:	password to unlock the key material
 */
struct ehd_keydec_request {
	char *keyfile, *digest, *cipher, *password;
#ifdef HAVE_LIBCRYPTO
	const EVP_CIPHER *s_cipher;
	const EVP_MD *s_digest;
#endif
	const unsigned char *d_salt, *d_text;
	hxmc_t *d_result;
	unsigned int d_keysize;
};

static pthread_mutex_t ehd_init_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long ehd_use_count;

static void __attribute__((constructor)) ehd_ident(void)
{
	if (getenv("LIBCRYPTMOUNT_IDENTIFY") != NULL)
		fprintf(stderr, "# " PACKAGE_NAME " " PACKAGE_VERSION "\n");
}

EXPORT_SYMBOL int cryptmount_init(void)
{
	int ret;

	pthread_mutex_lock(&ehd_init_lock);
	if (ehd_use_count == 0) {
		ret = HX_init();
		if (ret < 0) {
			pthread_mutex_unlock(&ehd_init_lock);
			return ret;
		}
#ifdef HAVE_LIBCRYPTO
		OpenSSL_add_all_algorithms();
		OpenSSL_add_all_ciphers();
		OpenSSL_add_all_digests();
#endif
	}
	++ehd_use_count;
	pthread_mutex_unlock(&ehd_init_lock);
	return 1;
}

EXPORT_SYMBOL void cryptmount_exit(void)
{
	pthread_mutex_lock(&ehd_init_lock);
	/*
	 * OpenSSL does not look refcounted and calling EVP_cleanup could
	 * upset other components in the program image.
	 */
	if (ehd_use_count == 0)
		fprintf(stderr, "%s: reference count is already zero!\n",
		        __func__);
	else if (--ehd_use_count == 0)
		HX_exit();
	pthread_mutex_unlock(&ehd_init_lock);
}

EXPORT_SYMBOL int ehd_mtinfo_get(struct ehd_mount_info *mt,
    enum ehd_mtinfo_opt opt, void *ptr)
{
	switch (opt) {
	case EHD_MTINFO_CONTAINER:
		*static_cast(const char **, ptr) = mt->container;
		break;
	case EHD_MTINFO_CRYPTONAME:
		*static_cast(const char **, ptr) = mt->crypto_name;
		break;
	case EHD_MTINFO_CRYPTODEV:
		*static_cast(const char **, ptr) = mt->crypto_device;
		break;
	case EHD_MTINFO_LOOPDEV:
		*static_cast(const char **, ptr) = mt->loop_device;
		break;
	case EHD_MTINFO_LOWERDEV:
		*static_cast(const char **, ptr) = mt->lower_device;
		break;
	default:
		return 0;
	}
	return 1;
}

/**
 * ehd_mtfree - free data associated with an EHD mount info block
 */
EXPORT_SYMBOL void ehd_mtinfo_free(struct ehd_mount_info *mt)
{
	free(mt->container);
	HXmc_free(mt->crypto_device);
	HXmc_free(mt->crypto_name);
	if (mt->loop_device != NULL)
		free(mt->loop_device);
	/*
	 * mt->lower_device is either NULL or pointing to
	 * container of loop_device - and thus must not be freed.
	 */
}

EXPORT_SYMBOL struct ehd_mount_request *ehd_mtreq_new(void)
{
	struct ehd_mount_request *rq;

	rq = calloc(1, sizeof(*rq));
	if (rq == NULL)
		return NULL;
	rq->last_stage = EHD_MTREQ_STAGE_MOUNT;
	return rq;
}

EXPORT_SYMBOL void ehd_mtreq_free(struct ehd_mount_request *rq)
{
	free(rq->container);
	free(rq->mountpoint);
	free(rq->fs_cipher);
	free(rq->fs_hash);
	free(rq->key_data);
	free(rq);
}

EXPORT_SYMBOL int ehd_mtreq_set(struct ehd_mount_request *rq,
    enum ehd_mtreq_opt opt, ...)
{
	va_list args;
	const void *orig;
	void *nv = NULL;

	va_start(args, opt);
	switch (opt) {
	case EHD_MTREQ_CONTAINER:
	case EHD_MTREQ_CRYPTONAME:
	case EHD_MTREQ_MOUNTPOINT:
	case EHD_MTREQ_FS_CIPHER:
	case EHD_MTREQ_FS_HASH:
	case EHD_MTREQ_FSTYPE:
	case EHD_MTREQ_MOUNT_OPTS:
		orig = va_arg(args, const char *);
		nv = HX_strdup(orig);
		if (nv == NULL && orig != NULL)
			goto out;
		break;
	case EHD_MTREQ_KEY_DATA:
		orig = va_arg(args, const void *);
		nv = HX_memdup(orig, rq->key_size);
		if (nv == NULL)
			goto out;
		free(rq->key_data);
		rq->key_data = nv;
		break;
	case EHD_MTREQ_KEY_SIZE:
		rq->key_size = va_arg(args, unsigned int);
		break;
	case EHD_MTREQ_TRUNC_KEYSIZE:
		rq->trunc_keysize = va_arg(args, unsigned int);
		break;
	case EHD_MTREQ_READONLY:
		rq->readonly = va_arg(args, unsigned int);
		break;
	case EHD_MTREQ_LOOP_HOOK:
		rq->loop_hook = va_arg(args, ehd_hook_fn_t);
		break;
	case EHD_MTREQ_HOOK_PRIV:
		rq->hook_priv = va_arg(args, void *);
		break;
	case EHD_MTREQ_CRYPTO_HOOK:
		rq->crypto_hook = va_arg(args, ehd_hook_fn_t);
		break;
	case EHD_MTREQ_LAST_STAGE:
		rq->last_stage = va_arg(args, enum ehd_mtreq_stage);
		break;
	case EHD_MTREQ_ALLOW_DISCARDS:
		rq->allow_discards = va_arg(args, unsigned int);
		break;
	}
	switch (opt) {
	case EHD_MTREQ_CONTAINER:
		free(rq->container);
		rq->container = nv;
		break;
	case EHD_MTREQ_CRYPTONAME:
		free(rq->crypto_name);
		rq->crypto_name = nv;
		break;
	case EHD_MTREQ_MOUNTPOINT:
		free(rq->container);
		rq->container = nv;
		break;
	case EHD_MTREQ_FS_CIPHER:
		free(rq->fs_cipher);
		rq->fs_cipher = nv;
		break;
	case EHD_MTREQ_FS_HASH:
		free(rq->fs_hash);
		rq->fs_hash = nv;
		break;
	case EHD_MTREQ_FSTYPE:
		free(rq->fstype);
		rq->fstype = nv;
		break;
	case EHD_MTREQ_MOUNT_OPTS:
		free(rq->mount_opts);
		rq->mount_opts = nv;
		break;
	default:
		break;
	}
	va_end(args);
	return 1;
 out:
	va_end(args);
	return -errno;
}

static int ehd_wait_for_file(const char *path)
{
	static const struct timespec delay = {0, 100000000};
	unsigned int retries = 50;
	struct stat sb;
	bool done = false;
	int ret;

	/* Nicer way to do these wait loops? libudev? */
	while (retries-- > 0) {
		ret = stat(path, &sb);
		if (ret == 0)
			break;
		ret = -errno;
		if (ret != -ENOENT)
			return -errno;
		if (!done) {
			w4rn("Waiting for %s to appear\n", path);
			done = true;
		}
		fprintf(stderr, ".");
		nanosleep(&delay, NULL);
	}
	if (ret == -ENOENT)
		w4rn("Device node %s was not created\n", path);
	return (ret == 0) ? 1 : ret;
}

/**
 * ehd_load - set up crypto device for an EHD container
 * @req:	parameters for setting up the mount
 * @mt:		EHD mount state
 */
EXPORT_SYMBOL int ehd_load(struct ehd_mount_request *req,
    struct ehd_mount_info **mtp)
{
	struct stat sb;
	int saved_errno, ret;
	struct ehd_mount_info *mt;

	if (stat(req->container, &sb) < 0) {
		l0g("Could not stat %s: %s\n", req->container, strerror(errno));
		return -errno;
	}

	*mtp = mt = calloc(1, sizeof(*mt));
	if (mt == NULL)
		goto out_err;
	if ((mt->container = HX_strdup(req->container)) == NULL)
		goto out_err;
	if (S_ISBLK(sb.st_mode)) {
		mt->loop_device  = NULL;
		mt->lower_device = req->container;
	} else {
		/* need losetup since cryptsetup needs block device */
		w4rn("Setting up loop device for file %s\n", req->container);
		ret = ehd_loop_setup(req->container, &mt->loop_device,
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

		ret = ehd_wait_for_file(mt->loop_device);
		if (ret <= 0)
			goto out_ser;
	}

	if (req->loop_hook != NULL) {
		ret = req->loop_hook(req, mt, req->hook_priv);
		if (ret <= 0)
			goto out_ser;
	}
	if (req->last_stage == EHD_MTREQ_STAGE_LOOP)
		return 1;

#ifdef HAVE_LIBCRYPTSETUP
	ret = ehd_dmcrypt_ops.load(req, mt);
#elif defined(HAVE_DEV_CGDVAR_H)
	ret = ehd_cgd_ops.load(req, mt);
#else
	ret = -EOPNOTSUPP;
#endif
	if (ret <= 0)
		goto out_ser;

	ret = ehd_wait_for_file(mt->crypto_device);
	if (ret <= 0)
		goto out_ser;

	if (req->crypto_hook != NULL) {
		ret = req->crypto_hook(req, mt, req->hook_priv);
		if (ret <= 0)
			goto out_ser;
	}
	if (req->last_stage == EHD_MTREQ_STAGE_CRYPTO)
		return 1;

	return ret;

 out_err:
	ret = -errno;
 out_ser:
	saved_errno = errno;
	if (mt != NULL) {
		ehd_unload(mt);
		ehd_mtinfo_free(mt);
	}
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
EXPORT_SYMBOL int ehd_unload(struct ehd_mount_info *mt)
{
	int ret, ret2;

	if (mt->crypto_device != NULL) {
#ifdef HAVE_LIBCRYPTSETUP
		ret = ehd_dmcrypt_ops.unload(mt);
#elif defined(HAVE_DEV_CGDVAR_H)
		ret = ehd_cgd_ops.unload(mt);
#else
		ret = -EOPNOTSUPP;
#endif
	} else {
		ret = 1;
	}
	/* Try to free loop device even if cryptsetup remove failed */
	if (mt->loop_device != NULL) {
		ret2 = ehd_loop_release(mt->loop_device);
		if (ret > 0)
			ret = ret2;
	}
	return ret;
}

#ifndef HAVE_LIBCRYPTSETUP
EXPORT_SYMBOL int ehd_is_luks(const char *device, bool blkdev)
{
	return -EINVAL;
}
#endif

#ifdef HAVE_LIBCRYPTO
static int ehd_decrypt_key2(struct ehd_keydec_request *par)
{
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	unsigned int out_cumul_len = 0;
	EVP_CIPHER_CTX ctx;
	int out_len = 0;
	hxmc_t *out;

	if (EVP_BytesToKey(par->s_cipher, par->s_digest, par->d_salt,
	    signed_cast(const unsigned char *, par->password),
	    (par->password == NULL) ? 0 : strlen(par->password),
	    1, key, iv) <= 0)
		return EHD_KEYDEC_OTHER;

	out = HXmc_meminit(NULL, par->d_keysize + par->s_cipher->block_size);
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, par->s_cipher, NULL, key, iv);
	EVP_DecryptUpdate(&ctx, signed_cast(unsigned char *,
		&out[out_len]), &out_len, par->d_text, par->d_keysize);
	out_cumul_len += out_len;
	EVP_DecryptFinal_ex(&ctx, signed_cast(unsigned char *,
		&out[out_len]), &out_len);
	out_cumul_len += out_len;
	HXmc_setlen(&out, out_cumul_len);
	EVP_CIPHER_CTX_cleanup(&ctx);

	par->d_result = out;
	return EHD_KEYDEC_SUCCESS;
}
#endif

EXPORT_SYMBOL int
ehd_keydec_run(struct ehd_keydec_request *par, hxmc_t **res)
{
#ifdef HAVE_LIBCRYPTO
	unsigned char *buf;
	struct stat sb;
	ssize_t i_ret;
	int fd, ret;

	if (par->digest == NULL)
		return EHD_KEYDEC_NODIGEST;
	if (par->cipher == NULL)
		return EHD_KEYDEC_NOCIPHER;
	par->s_digest = EVP_get_digestbyname(par->digest);
	if (par->s_digest == NULL)
		return EHD_KEYDEC_NODIGEST;
	par->s_cipher = EVP_get_cipherbyname(par->cipher);
	if (par->s_cipher == NULL)
		return EHD_KEYDEC_NOCIPHER;

	if ((fd = open(par->keyfile, O_RDONLY)) < 0)
		return -errno;
	if (fstat(fd, &sb) < 0) {
		ret = -errno;
		l0g("stat: %s\n", strerror(errno));
		goto out;
	}
	if ((buf = malloc(sb.st_size)) == NULL) {
		ret = -errno;
		l0g("%s: malloc %zu: %s\n", __func__, sb.st_size,
		    strerror(errno));
		goto out;
	}
	if ((i_ret = read(fd, buf, sb.st_size)) != sb.st_size) {
		ret = (i_ret < 0) ? -errno : EHD_KEYDEC_OTHER;
		l0g("Incomplete read of %u bytes got %Zd bytes\n",
		    sb.st_size, i_ret);
		goto out2;
	}

	par->d_salt    = &buf[strlen("Salted__")];
	par->d_text    = par->d_salt + PKCS5_SALT_LEN;
	par->d_keysize = sb.st_size - (par->d_text - buf);
	ret = ehd_decrypt_key2(par);
	*res = par->d_result;
 out2:
	free(buf);
 out:
	close(fd);
	return ret;
#else
	l0g("%s called, but library built without openssl\n", __func__);
	return -EINVAL;
#endif
}

EXPORT_SYMBOL const char *ehd_keydec_strerror(int e)
{
	if (e <= 0)
		return strerror(-e);
	switch (e) {
	case EHD_KEYDEC_NODIGEST:
		return "Unknown digest";
	case EHD_KEYDEC_NOCIPHER:
		return "Unknown cipher";
	case EHD_KEYDEC_OTHER:
		return "Other unspecified error";
	default:
		return "Unknown error code";
	}
}

EXPORT_SYMBOL struct ehd_keydec_request *ehd_kdreq_new(void)
{
	struct ehd_keydec_request *rq;

	rq = calloc(1, sizeof(*rq));
	if (rq == NULL)
		return NULL;
	return rq;
}

EXPORT_SYMBOL void ehd_kdreq_free(struct ehd_keydec_request *rq)
{
	free(rq->keyfile);
	free(rq->cipher);
	free(rq->digest);
	free(rq->password);
	free(rq);
}

EXPORT_SYMBOL int ehd_kdreq_set(struct ehd_keydec_request *rq,
    enum ehd_kdreq_opt opt, ...)
{
	va_list args;
	const void *orig;
	void *nv = NULL;

	va_start(args, opt);
	switch (opt) {
	case EHD_KDREQ_KEYFILE ... EHD_KDREQ_PASSWORD:
		orig = va_arg(args, const char *);
		nv = HX_strdup(orig);
		if (nv == NULL && orig != NULL)
			goto out;
		break;
	}
	switch (opt) {
	case EHD_KDREQ_KEYFILE:
		free(rq->keyfile);
		rq->keyfile = nv;
		break;
	case EHD_KDREQ_CIPHER:
		free(rq->cipher);
		rq->cipher = nv;
		break;
	case EHD_KDREQ_DIGEST:
		free(rq->digest);
		rq->digest = nv;
		break;
	case EHD_KDREQ_PASSWORD:
		free(rq->password);
		rq->password = nv;
		break;
	}
	va_end(args);
	return 1;
 out:
	va_end(args);
	return -errno;
}

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
			return EHD_SECURITY_SUBPAR;

	return EHD_SECURITY_UNSPEC;
}

/**
 * cipher_digest_security - returns the secure level of a cipher/digest
 * @s:	name of the cipher or digest specification
 * 	(can either be OpenSSL or cryptsetup name)
 *
 * Returns the lowest security class ("weakest element of the chain")
 * of the compound string.
 */
EXPORT_SYMBOL int ehd_cipherdigest_security(const char *s)
{
	char *base, *tmp, *wp;
	unsigned int verdict, ret;

	if (s == NULL)
		return EHD_SECURITY_UNSPEC;
	if ((base = HX_strdup(s)) == NULL)
		return -errno;

	tmp = base;
	verdict = EHD_SECURITY_UNSPEC;
	while ((wp = HX_strsep(&tmp, ",-.:_")) != NULL) {
		ret = __cipher_digest_security(wp);
		if (verdict == EHD_SECURITY_UNSPEC)
			verdict = ret;
		else if (ret < verdict)
			verdict = ret;
	}

	free(base);
	return verdict;
}

static struct {
	struct sigaction oldact;
	bool echo;
	int fd;
} ehd_pwq_restore;

static void ehd_password_stop(int s)
{
	struct termios ti;

	if (!ehd_pwq_restore.echo)
		return;
	if (tcgetattr(ehd_pwq_restore.fd, &ti) == 0) {
		ti.c_lflag |= ECHO;
		tcsetattr(ehd_pwq_restore.fd, TCSANOW, &ti);
	}
	sigaction(s, &ehd_pwq_restore.oldact, NULL);
	if (s != 0)
		kill(0, s);
}

static hxmc_t *__ehd_get_password(FILE *fp)
{
	hxmc_t *ret = NULL;
	memset(&ehd_pwq_restore, 0, sizeof(ehd_pwq_restore));
	ehd_pwq_restore.fd = fileno(fp);

	if (isatty(fileno(fp))) {
		struct sigaction sa;
		struct termios ti;

		if (tcgetattr(fileno(fp), &ti) == 0) {
			ehd_pwq_restore.echo = ti.c_lflag & ECHO;
			if (ehd_pwq_restore.echo) {
				sigemptyset(&sa.sa_mask);
				sa.sa_handler = ehd_password_stop;
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
	ehd_password_stop(0);
	return ret;
}

EXPORT_SYMBOL hxmc_t *ehd_get_password(const char *prompt)
{
	hxmc_t *ret;

	printf("%s", (prompt != NULL) ? prompt : "Password: ");
	fflush(stdout);
	ret = __ehd_get_password(stdin);
	printf("\n");
	return ret;
}
