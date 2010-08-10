#ifndef PMT_PAM_MOUNT_H
#define PMT_PAM_MOUNT_H 1

#include <sys/types.h>
#include <limits.h>
#include <stdbool.h>
#include <libHX/list.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include "config.h"

#ifdef HAVE_VISIBILITY_HIDDEN
#	define EXPORT_SYMBOL __attribute__((visibility("default")))
#else
#	define EXPORT_SYMBOL
#endif

#ifndef S_IRXG
#	define S_IRXG (S_IRGRP | S_IXGRP)
#endif
#ifndef S_IRXO
#	define S_IRXO (S_IROTH | S_IXOTH)
#endif
#define sizeof_z(x) (sizeof(x) - 1)

/*
 * So many programs trash a useful $PATH (including mount(8)),
 * so just provide our own.
 */
#define PMT_DFL_PATH \
	"/usr/local/libexec/hxtools:/usr/local/lib/hxtools:" \
	"/usr/local/sbin:/usr/local/bin:" \
	"/usr/libexec/hxtools:/usr/lib/hxtools:" \
	"/usr/sbin:/usr/bin:/sbin:/bin"
#define PMT_DFL_DMCRYPT_CIPHER "aes-cbc-essiv:sha256"
#define PMT_DFL_FSK_CIPHER     "aes-256-cbc"
#define PMT_DFL_FSK_HASH       "sha1"

/* Note that you will also need to change PMPREFIX in pmvarrun.c then! */
#define l0g(fmt, ...) \
	misc_log(("%s(%s:%u): " fmt), pmtlog_prefix, HX_basename(__FILE__), \
	__LINE__, ## __VA_ARGS__)
#define w4rn(fmt, ...) \
	misc_warn(("%s(%s:%u): " fmt), pmtlog_prefix, HX_basename(__FILE__), \
	__LINE__, ## __VA_ARGS__)

struct HXdeque;
struct HXformatmap;
struct HXproc;
struct loop_info64;

enum auth_type {
	GET_PASS,
	USE_FIRST_PASS,
	TRY_FIRST_PASS,
	SOFT_TRY_PASS,
};

enum command_type {
	CMD_SMBMOUNT,
	CMD_SMBUMOUNT,
	CMD_CIFSMOUNT,
	CMD_NCPMOUNT,
	CMD_NCPUMOUNT,
	CMD_FUSEMOUNT,
	CMD_FUSEUMOUNT,
	CMD_LCLMOUNT,
	CMD_CRYPTMOUNT,
	CMD_CRYPTUMOUNT,
	CMD_NFSMOUNT,
	CMD_UMOUNT,
	CMD_PMHELPER,
	CMD_FSCK,
	CMD_PMVARRUN,
	CMD_FD0SSH,
	CMD_OFL,
	_CMD_MAX,
	CMD_NONE,
};

enum {
	/* src */
	PMTLOG_ERR = 0,
	PMTLOG_DBG,
	PMTLOG_SRCMAX,

	/* dst */
	PMTLOG_SYSLOG = 0,
	PMTLOG_STDERR,
	PMTLOG_DSTMAX,
};

struct vol {
	struct HXlist_head list;
	enum command_type type;
	/* true if configuration from global config, false if luserconf */
	bool globalconf;
	/* set, so that umount can rmdir it */
	bool created_mntpt;
	/* expansion already took place */
	bool is_expanded;
	/* was handed off to mount_op() */
	bool mnt_processed;
	const char *user;
	char *fstype, *server, *volume, *mountpoint, *cipher;
	char *fs_key_cipher, *fs_key_hash, *fs_key_path;
	/* May be NULL if no options */
	struct HXclist_head options;
	bool use_fstab;
	bool uses_ssh;
	bool noroot;
};

/**
 * @sig_hup:	send SIGHUP to processes keeping mountpoint open
 * @sig_term:	send SIGTERM - " -
 * @sig_kill:	send SIGKILL - " -
 * @sig_wait:	wait this many seconds between sending signals,
 * 		in microseconds
 */
struct config {
	/* user logging in */
	char *user;
	unsigned int debug;
	bool mkmntpoint, rmdir_mntpt;
	bool seen_mntoptions_require, seen_mntoptions_allow;
	hxmc_t *luserconf;
	struct HXdeque *command[_CMD_MAX];
	struct HXmap *options_require, *options_allow, *options_deny;
	struct HXclist_head volume_list;
	int level;
	char *msg_authpw, *msg_sessionpw, *path;

	bool sig_hup, sig_term, sig_kill;
	unsigned int sig_wait;
};

struct kvp {
	char *key, *value;
	struct HXlist_head list;
};

/**
 * struct ehd_request - mapping and mount request for EHD
 * @mountpoint:	where to mount EHD
 * @fs_cipher:	cipher used for filesystem (cryptsetup name)
 * @fs_hash:	hash used for filesystem (cryptsetup name)
 * @container:	path to disk image
 * @key_data:	key material
 * @key_size:	size of key data, in bytes
 * @trunc_keysize:	extra cryptsetup instruction for truncation (in bytes)
 * @readonly:	create readonly mount?
 */
struct ehd_mtreq {
	const char *mountpoint;
	const char *fs_cipher, *fs_hash, *container;
	const void *key_data;
	unsigned int key_size, trunc_keysize;
	bool readonly;
};

/**
 * struct ehd_mount - EHD mount info
 * @container:		path to disk image
 * @lower_device:	link to either @container if a block device,
 * 			otherwise points to @loop_device.
 * @loop_device:	loop device that was created, if any
 * @crypto_name:	crypto device that was created (basename only)
 * @crypto_device:	full path to the crypto device
 */
struct ehd_mount {
	char *container;
	const char *lower_device;
	char *loop_device;
	hxmc_t *crypto_name;
	hxmc_t *crypto_device;
};

struct ehd_crypto_ops {
	int (*load)(const struct ehd_mtreq *, struct ehd_mount *);
	int (*unload)(const struct ehd_mount *);
};

typedef int (mount_op_fn_t)(const struct config *, struct vol *,
	struct HXformat_map *, const char *);

/*
 *
 */
static inline void format_add(struct HXformat_map *table, const char *key,
    const char *value)
{
	if (value == NULL)
		HXformat_add(table, key, "", HXTYPE_STRING);
	else
		HXformat_add(table, key, value, HXTYPE_STRING | HXFORMAT_IMMED);
}

static inline const char *znul(const char *s)
{
	return (s == NULL) ? "(null)" : s;
}

/*
 *	CRYPTO.C
 */
extern int ehd_load(const struct ehd_mtreq *, struct ehd_mount *);
extern int ehd_unload(const struct ehd_mount *);
extern void ehd_mtfree(struct ehd_mount *);
extern hxmc_t *ehd_decrypt_key(const char *, const char *, const char *,
	hxmc_t *);
extern unsigned int cipher_digest_security(const char *);
extern hxmc_t *pmt_get_password(const char *);

/*
 *	CRYPTO-*.C
 */
extern const struct ehd_crypto_ops ehd_cgd_ops;
extern const struct ehd_crypto_ops ehd_dmcrypt_ops;

extern int dmc_is_luks(const char *, bool);

/*
 *	LOOP.C
 */
extern size_t pmt_block_getsize64(const char *);
extern int pmt_loop_setup(const char *, char **, bool);
extern int pmt_loop_release(const char *);

/*
 *	LOG.C
 */
extern const char *pmtlog_prefix;
extern bool pmtlog_path[PMTLOG_SRCMAX][PMTLOG_DSTMAX];

extern int misc_log(const char *, ...);
extern int misc_warn(const char *, ...);

/*
 *	MISC.C
 */
extern void arglist_add(struct HXdeque *, const char *,
	const struct HXformat_map *);
extern struct HXdeque *arglist_build(const struct HXdeque *,
	const struct HXformat_map *);
extern void arglist_log(const struct HXdeque *);
extern void arglist_llog(const char *const *);
extern bool kvplist_contains(const struct HXclist_head *, const char *);
extern char *kvplist_get(const struct HXclist_head *, const char *);
extern void kvplist_genocide(struct HXclist_head *);
extern hxmc_t *kvplist_to_str(const struct HXclist_head *);
extern void misc_add_ntdom(struct HXformat_map *, const char *);
extern void misc_dump_id(const char *);
extern int pmt_fileop_exists(const char *);
extern int pmt_fileop_owns(const char *, const char *);
extern char *relookup_user(const char *);
extern long str_to_long(const char *);
extern void *xmalloc(size_t);
extern void *xrealloc(void *, size_t);
extern char *xstrdup(const char *);

/*
 *	MTAB.C
 */
/* Enum constants must match order of /etc/mtab and /etc/cmtab, respectively. */
enum smtab_field {
	SMTABF_CONTAINER = 0,
	SMTABF_MOUNTPOINT,
	__SMTABF_MAX,
};

enum cmtab_field {
	CMTABF_MOUNTPOINT = 0,
	CMTABF_CONTAINER,
	CMTABF_LOOP_DEV,
	CMTABF_CRYPTO_DEV,
	__CMTABF_MAX,
};

extern int pmt_smtab_add(const char *, const char *,
	const char *, const char *);
extern int pmt_smtab_remove(const char *, enum smtab_field);
extern int pmt_smtab_mounted(const char *, const char *,
	int (*)(const char *, const char *));
extern int pmt_cmtab_add(const char *, const char *,
	const char *, const char *);
extern int pmt_cmtab_get(const char *, enum cmtab_field,
	char **, char **, char **, char **);
extern int pmt_cmtab_remove(const char *, enum cmtab_field);
extern int pmt_cmtab_mounted(const char *, const char *);

/*
 *	MOUNT.C
 */
extern mount_op_fn_t do_mount, do_unmount;
extern int fstype_nodev(const char *);
extern int mount_op(mount_op_fn_t *, const struct config *, struct vol *,
	const char *);
extern void umount_final(struct config *);
extern int pmt_already_mounted(const struct config *,
	const struct vol *, struct HXformat_map *);
extern hxmc_t *pmt_vol_to_dev(const struct vol *);
extern bool fstype_icase(const char *);
extern bool fstype2_icase(enum command_type);

/*
 *	OFL-LIB.C
 */
extern int (*ofl_printf)(const char *, ...);
extern bool ofl(const char *, unsigned int);

/*
 *	PAM_MOUNT.C
 */
#ifndef HAVE_VISIBILITY_HIDDEN
	/* Workaround Xserver issue */
#	define Debug pmt_debug
#endif
extern unsigned int Debug;
extern struct config Config;

/*
 *	RDCONF1.C
 */
extern bool expandconfig(const struct config *);
extern void initconfig(struct config *);
extern bool readconfig(const char *, bool, struct config *);
extern void freeconfig(struct config *);

/*
 *	RDCONF2.C
 */
extern bool luserconf_volume_record_sane(const struct config *, const struct vol *);
extern bool volume_record_sane(const struct config *, const struct vol *);

/*
 *	SPAWN.C
 */
extern const struct HXproc_ops pmt_spawn_ops, pmt_dropprivs_ops;

extern int pmt_spawn_dq(struct HXdeque *, struct HXproc *);

#endif /* PMT_PAM_MOUNT_H */
