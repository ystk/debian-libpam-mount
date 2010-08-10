/*
 *	Copyright © Jan Engelhardt, 2008 - 2010
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libHX/ctype_helper.h>
#include <libHX/defs.h>
#include <libHX/proc.h>
#include <libHX/string.h>
#include <libcryptsetup.h>
#include "pam_mount.h"

/**
 * dmc_is_luks - check if @path points to a LUKS volume (cf. normal dm-crypt)
 * @path:	path to the crypto container
 * @blkdev:	path is definitely a block device
 */
int dmc_is_luks(const char *path, bool blkdev)
{
	struct crypt_device *cd;
	const char *device = path;
	char *loop_device;
	int ret;

	if (!blkdev) {
		ret = pmt_loop_setup(path, &loop_device, true);
		if (ret == 0) {
			fprintf(stderr, "No free loop device\n");
			return -ENXIO;
		} else if (ret < 0) {
			fprintf(stderr, "%s: could not set up loop device: %s\n",
			        __func__, strerror(-ret));
			return ret;
		}
		device = loop_device;
	}

	ret = crypt_init(&cd, device);
	if (ret == 0) {
		ret = crypt_load(cd, CRYPT_LUKS1, NULL);
		if (ret == -EINVAL)
			ret = false;
		else if (ret == 0)
			ret = true;
		/* else keep ret as-is */
		crypt_free(cd);
	}
	if (!blkdev)
		pmt_loop_release(loop_device);
	return ret;
}

static hxmc_t *dmc_crypto_name(const char *s)
{
	hxmc_t *ret;
	char *p;

	ret = HXmc_strinit(s);
	for (p = ret; *p != '\0'; ++p)
		if (!HX_isalnum(*p))
			*p = '_';
	return ret;
}

static bool dmc_run(const struct ehd_mtreq *req, struct ehd_mount *mt)
{
	struct crypt_device *cd;
	unsigned int flags = 0;
	char *cipher = NULL, *mode;
	int ret;

	ret = crypt_init(&cd, mt->lower_device);
	if (ret < 0) {
		fprintf(stderr, "crypt_init: %s\n", strerror(-ret));
		return false;
	}
	if (req->readonly)
		flags |= CRYPT_ACTIVATE_READONLY;

	ret = crypt_load(cd, CRYPT_LUKS1, NULL);
	if (ret == 0) {
		ret = crypt_activate_by_passphrase(cd, mt->crypto_name,
		      CRYPT_ANY_SLOT, req->key_data, req->key_size, flags);
		if (ret < 0) {
			fprintf(stderr, "crypt_activate_by_passphrase: %s\n",
			        strerror(-ret));
			goto out;
		}
	} else {
		struct crypt_params_plain params = {.hash = req->fs_hash};

		cipher = HX_strdup(req->fs_cipher);
		if (cipher == NULL) {
			ret = -errno;
			goto out;
		}
		/* stuff like aes-cbc-essiv:sha256 => aes, cbc-essiv:sha256 */
		mode = strchr(cipher, '-');
		if (mode != NULL)
			*mode++ = '\0';
		else
			mode = "plain";

		ret = crypt_format(cd, CRYPT_PLAIN, cipher, mode, NULL, NULL,
		      req->trunc_keysize, &params);
		if (ret < 0) {
			fprintf(stderr, "crypt_format: %s\n", strerror(-ret));
			goto out;
		}

		if (strcmp(req->fs_hash, "plain") == 0)
			ret = crypt_activate_by_volume_key(cd, mt->crypto_name,
			      req->key_data, req->key_size, flags);
		else
			ret = crypt_activate_by_passphrase(cd, mt->crypto_name,
			      CRYPT_ANY_SLOT, req->key_data, req->key_size,
			      flags);
		if (ret < 0) {
			fprintf(stderr, "crypt_activate: %s\n", strerror(-ret));
			goto out;
		}
	}

 out:
	free(cipher);
	crypt_free(cd);
	return ret >= 0 ? true : false;
}

static int dmc_load(const struct ehd_mtreq *req, struct ehd_mount *mt)
{
	mt->crypto_name = dmc_crypto_name(mt->container);
	w4rn("Using %s as dmdevice name\n", mt->crypto_name);
	mt->crypto_device = HXmc_strinit("/dev/mapper/");
	HXmc_strcat(&mt->crypto_device, mt->crypto_name);

	return dmc_run(req, mt);
}

static int dmc_unload(const struct ehd_mount *mt)
{
	struct crypt_device *cd;
	const char *cname;
	int ret;

	ret = crypt_init(&cd, mt->crypto_device);
	if (ret < 0)
		return ret;

	cname = (mt->crypto_name != NULL) ? mt->crypto_name :
	        HX_basename(mt->crypto_device);
	ret = crypt_deactivate(cd, cname);
	crypt_free(cd);
	return (ret < 0) ? ret : 1;
}

const struct ehd_crypto_ops ehd_dmcrypt_ops = {
	.load   = dmc_load,
	.unload = dmc_unload,
};
