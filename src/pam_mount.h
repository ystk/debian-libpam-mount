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

/* Note that you will also need to change PMPREFIX in pmvarrun.c then! */
#define l0g(fmt, ...) \
	ehd_err(("(%s:%u): " fmt), HX_basename(__FILE__), \
	__LINE__, ## __VA_ARGS__)
#define w4rn(fmt, ...) \
	ehd_dbg(("(%s:%u): " fmt), HX_basename(__FILE__), \
	__LINE__, ## __VA_ARGS__)

struct HXdeque;
struct HXformatmap;
struct HXproc;
struct loop_info64;

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

/**
 * @server:	server name, if any
 * @volume:	path relative to server, or full path in case @server is empty
 * @combopath:	concatenation of @server and @volume dependent upon @fstype
 */
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
	char *fstype, *server, *volume, *combopath, *mountpoint, *cipher;
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
 *	BDEV.C
 */
extern size_t pmt_block_getsize64(const char *);

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
extern bool pmt_fileop_exists(const char *);
extern bool pmt_fileop_isreg(const char *);
extern bool pmt_fileop_owns(const char *, const char *);
extern char *relookup_user(const char *);
extern long str_to_long(const char *);
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

enum {
	PMT_BY_CONTAINER = 1 << 0,
	PMT_BY_CRYPTODEV = 1 << 1,
};

struct ehd_mount_info;

extern int pmt_smtab_add(const char *, const char *,
	const char *, const char *);
extern int pmt_smtab_remove(const char *, enum smtab_field);
extern int pmt_smtab_mounted(const char *, const char *,
	int (*)(const char *, const char *));
extern int pmt_cmtab_add(struct ehd_mount_info *);
extern int pmt_cmtab_get(const char *, enum cmtab_field,
	char **, char **, char **, char **);
extern int pmt_cmtab_remove(const char *);
extern int pmt_cmtab_mounted(const char *, const char *);
extern const char *pmt_cmtab_path(void);
extern const char *pmt_smtab_path(void);
extern const char *pmt_kmtab_path(void);

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
