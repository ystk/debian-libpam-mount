#ifndef _CMT_INTERNAL_H
#define _CMT_INTERNAL_H 1

#include <stdbool.h>
#include <libHX/string.h>
#include "libcryptmount.h"

/**
 * struct ehd_mount - EHD mount info
 * @container:		path to disk image
 * @lower_device:	link to either @container if a block device,
 * 			otherwise points to @loop_device.
 * @loop_device:	loop device that was created, if any
 * @crypto_name:	crypto device that was created (basename only)
 * @crypto_device:	full path to the crypto device
 * @mountpoint:		assigned mountpoint
 */
struct ehd_mount_info {
	char *container;
	const char *lower_device;
	char *loop_device;
	hxmc_t *crypto_name;
	hxmc_t *crypto_device;
	hxmc_t *mountpoint;
};

/**
 * struct ehd_mount_request - mapping and mount request for EHD
 * @container:		path to disk image
 * @fstype:		filesystem type
 * @mount_opts:		mount options for fs
 * @mountpoint:		where to mount the volume on
 * @fs_cipher:		cipher used for filesystem, if any. (cryptsetup name)
 * @fs_hash:		hash used for filesystem, if any. (cryptsetup name)
 * @key_data:		key material/password
 * @key_size:		size of key data, in bytes
 * @trunc_keysize:	extra cryptsetup instruction for truncation (in bytes)
 * @loop_hook:		hook function to run after loop device setup
 * @crypto_hook:	hook function to run after crypto device setup
 * @hook_priv:		user data
+ * @last_stage:		stop after setup of given component
 * @readonly:		whether to create a readonly vfsmount
 * @allow_discards:	allow fs trim requests
 */
struct ehd_mount_request {
	char *container, *crypto_name, *fstype, *mount_opts, *mountpoint;
	char *fs_cipher, *fs_hash;
	void *key_data;
	ehd_hook_fn_t loop_hook, crypto_hook;
	void *hook_priv;
	unsigned int key_size, trunc_keysize;
	enum ehd_mtreq_stage last_stage;
	bool readonly, allow_discards;
};

struct ehd_crypto_ops {
	int (*load)(const struct ehd_mount_request *, struct ehd_mount_info *);
	int (*unload)(const struct ehd_mount_info *);
};

extern const struct ehd_crypto_ops ehd_cgd_ops;
extern const struct ehd_crypto_ops ehd_dmcrypt_ops;

#endif /* _CMT_INTERNAL_H */
