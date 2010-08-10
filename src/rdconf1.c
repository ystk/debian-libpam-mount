/*
 *	Copyright © Jan Engelhardt, 2006 - 2009
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#	include <fstab.h>
#elif defined(__linux__)
#	include <mntent.h>
#endif
#include <libHX.h>
#include <libHX/libxml_helper.h>
#include "pam_mount.h"

/* Definitions */
enum {
	CONTEXT_GLOBAL = 0,
	CONTEXT_LUSER,
};

enum fstab_field {
	FSTAB_VOLUME,
	FSTAB_MNTPT,
	FSTAB_FSTYPE,
	FSTAB_OPTS,
};

enum {
	CMDA_AUTHPW,
	CMDA_SESSIONPW,
	CMDA_PATH,
	CMDA_LOGOUT_SIGHUP,
	CMDA_LOGOUT_SIGTERM,
	CMDA_LOGOUT_SIGKILL,
	CMDA_LOGOUT_WAIT,
};

enum {
	OPT_MAP_FLAGS = HXMAP_SCKEY,
};

struct callbackmap {
	const char *name;
	const char *(*func)(xmlNode *, struct config *, unsigned int);
	unsigned int cmd;
};

struct pmt_command {
	enum command_type type;
	const char *fs, *def[11];
	/*
	 * You will need to enlarge @def whenever the compiler
	 * (rightfully) complains.
	 */
};

/* Functions */
static int rc_volume_cond_ext(const struct passwd *, xmlNode *);

/* Variables */
static const struct callbackmap cf_tags[];
static const struct pmt_command default_command[];

//-----------------------------------------------------------------------------
/**
 * expand_home -
 * @user:	username to use for home directory lookup
 * @path:	pathname to expand
 * @size:	size of @path
 *
 * Expands tildes in @path to the user home directory and updates @path.
 * Returns @dest.
 */
static bool expand_home(const char *user, char **path_pptr)
{
	char *buf, *path = *path_pptr;
	struct passwd *pe;
	size_t size;

	if (path == NULL)
		return true;
	if (*path != '~')
		return true;
	if ((pe = getpwnam(user)) == NULL) {
		l0g("Could not lookup account info for %s\n", user);
		return false;
	}
	size = strlen(pe->pw_dir) + strlen(path) + 1;
	if ((buf = xmalloc(size)) == NULL) {
		l0g("%s\n", strerror(errno));
		return NULL;
	}
	snprintf(buf, size, "%s%s", pe->pw_dir, path + 1);
	free(path);
	*path_pptr = buf;
	return true;
}

/**
 * expand_user -
 * @user:	username to substitue for placeholder
 * @dest:	buffer to operate on
 * @size:	size of @dest
 *
 * Substitutes all occurrences of %(USER) by the username. Returns NULL on
 * failure, otherwise @dest.
 *
 * (This should probably be done by the fmt_ptrn stuff, but is not at the
 * moment due to to-XML transition period.)
 */
static bool expand_user(const char *user, char **dest_pptr,
    const struct HXformat_map *vinfo)
{
	hxmc_t *tmp = NULL;

	if (*dest_pptr == NULL)
		return true;
	HXformat2_aprintf(vinfo, &tmp, *dest_pptr);
	*dest_pptr = xstrdup(tmp);
	HXmc_free(tmp);
	return true;
}

/**
 * expandconfig -
 * @config:	configuration structure
 *
 * This function will expand variables in attributes itself.
 * Like, turning <volume server="w2k3" path="%(USER)"
 * mountpoint="~" /> into path="joe" mountpoint="/home/joe".
 */
bool expandconfig(const struct config *config)
{
	const char *u = config->user;
	struct HXformat_map *vinfo;
	struct passwd *pe;
	struct group *ge;
	struct kvp *kvp;
	struct vol *vpt;

	if ((vinfo = HXformat_init()) == NULL)
		return false;
	if ((pe = getpwnam(u)) == NULL) {
		l0g("You do not exist? %s? %s.\n", u, strerror(errno));
		goto rfalse;
	}

	HXformat_add(vinfo, "USER", u, HXTYPE_STRING);
	HXformat_add(vinfo, "USERUID", reinterpret_cast(void *,
		static_cast(long, pe->pw_uid)), HXTYPE_UINT | HXFORMAT_IMMED);
	HXformat_add(vinfo, "USERGID", reinterpret_cast(void *,
		static_cast(long, pe->pw_gid)), HXTYPE_UINT | HXFORMAT_IMMED);
	ge = getgrgid(pe->pw_gid);
	format_add(vinfo, "GROUP", (ge != NULL) ? ge->gr_name : "");
	misc_add_ntdom(vinfo, u);

	HXlist_for_each_entry(vpt, &config->volume_list, list) {
		if (vpt->is_expanded)
			continue;
		vpt->is_expanded = true;
		if (!expand_user(u, &vpt->server, vinfo) ||
		    !expand_home(u, &vpt->volume) ||
		    !expand_user(u, &vpt->volume, vinfo) ||
		    !expand_home(u, &vpt->mountpoint) ||
		    !expand_user(u, &vpt->mountpoint, vinfo) ||
		    !expand_home(u, &vpt->fs_key_path) ||
		    !expand_user(u, &vpt->fs_key_path, vinfo) ||
		    !expand_user(u, &vpt->fs_key_cipher, vinfo))
			goto rfalse;

		/*
		 * Substitution on the key seems odd indeed, and was not
		 * originally intended. But it should be done, since the
		 * option separator is notalways ",", e.g. with AUFS.
		 * Least Surprise says: do the expansion on the key
		 * nevertheless.
		 */
		HXlist_for_each_entry(kvp, &vpt->options, list)
			if (!expand_user(u, &kvp->key, vinfo) ||
			    !expand_user(u, &kvp->value, vinfo))
				goto rfalse;
	}

	HXformat_free(vinfo);
	return true;
 rfalse:
	HXformat_free(vinfo);
	return false;
}

static void volume_free(struct vol *vol)
{
	kvplist_genocide(&vol->options);
	free(vol->fstype);
	free(vol->server);
	free(vol->volume);
	free(vol->cipher);
	free(vol->fs_key_cipher);
	free(vol->fs_key_hash);
	free(vol->fs_key_path);
	free(vol);
}

/**
 * freeconfig -
 * @config:	config struct
 *
 * All dynamically allocated memory in the structure is freed.
 * The caller must ensure HX_init had been called previously.
 */
void freeconfig(struct config *config)
{
	struct HXdeque *cmd;
	struct vol *vol, *next;
	unsigned int i;

	HXmc_free(config->luserconf);

	for (i = 0; i < _CMD_MAX; ++i) {
		/*
		 * This comment shall denote the awareness of a slight memory
		 * leak. In initconfig(), all strings of a command are
		 * duplicated when added to the list, while here we only free
		 * the first element. Because if the default hardcoded argument
		 * list is overriden using .conf.xml, only the first element is
		 * allocated and the rest are pointers to the same memory
		 * block.
		 */
		if ((cmd = config->command[i]) == NULL)
			continue;
		if (cmd->items > 0)
			free(cmd->first->ptr);
		HXdeque_free(cmd);
	}

	HXlist_for_each_entry_safe(vol, next, &config->volume_list, list)
		volume_free(vol);

	HXmap_free(config->options_allow);
	HXmap_free(config->options_require);
	HXmap_free(config->options_deny);
	free(config->user);
	free(config->msg_authpw);
	free(config->msg_sessionpw);
	free(config->path);
	memset(config, 0, sizeof(*config));
	HX_exit();
}

/**
 * str_to_optlist -
 * @optlist:	destination list
 * @str:	string to parse
 *
 * Break down @str into its option. This function modifies @str in-place.
 * This is ok, since it is already an allocated string (i.e. does belong to
 * pam_mount). Caller frees it anyway right away.
 */
static bool str_to_optkv(struct HXclist_head *optlist, char *str)
{
	char *value, *ptr;
	struct kvp *kvp;

	if (str == NULL || *str == '\0')
		return true;

	while ((ptr = HX_strsep(&str, ",")) != NULL) {
		kvp = xmalloc(sizeof(struct kvp));
		if (kvp == NULL)
			return false;
		HXlist_init(&kvp->list);
		value = strchr(ptr, '=');
		if (value != NULL) {
			*value++ = '\0';
			kvp->key   = xstrdup(ptr);
			kvp->value = xstrdup(value);
			if (kvp->key == NULL || kvp->value == NULL)
				goto out;
			HXclist_push(optlist, &kvp->list);
		} else {
			kvp->key = xstrdup(ptr);
			if (kvp->key == NULL)
				goto out;
			kvp->value = NULL;
			HXclist_push(optlist, &kvp->list);
		}
	}

	return true;
 out:
	free(kvp->key);
	free(kvp->value);
	free(kvp);
	return false;
}

static bool str_to_optlist(struct HXmap *optlist, char *str)
{
	char *value, *ptr;

	if (str == NULL || *str == '\0')
		return true;

	while ((ptr = HX_strsep(&str, ",")) != NULL) {
		value = strchr(ptr, '=');
		if (value != NULL) {
			*value++ = '\0';
			HXmap_add(optlist, ptr, value);
		} else {
			HXmap_add(optlist, ptr, NULL);
		}
	}

	return true;
}

void initconfig(struct config *config)
{
	unsigned int i, j;
	char options_allow[]   = "nosuid,nodev";
	char options_require[] = "nosuid,nodev";

	memset(config, 0, sizeof(*config));
	config->debug      = true;
	config->mkmntpoint = true;

	config->msg_authpw    = xstrdup("pam_mount password:");
	config->msg_sessionpw = xstrdup("reenter password for pam_mount:");

	config->path = xstrdup(PMT_DFL_PATH);

	/* Initialize all. Makes it easier. */
	for (i = 0; i < _CMD_MAX; ++i)
		if ((config->command[i] = HXdeque_init()) == NULL)
			perror("malloc");

	for (i = 0; default_command[i].type != -1; ++i) {
		struct HXdeque *cmd = config->command[default_command[i].type];

		if (cmd->items > 0)
			/*
			 * Already initialized by an earlier entry
			 * with same type.
			 */
			continue;

		for (j = 0; default_command[i].def[j] != NULL; ++j)
			HXdeque_push(cmd, xstrdup(default_command[i].def[j]));
	}

	config->options_allow   = HXmap_init(HXMAPT_DEFAULT, OPT_MAP_FLAGS);
	config->options_require = HXmap_init(HXMAPT_DEFAULT, OPT_MAP_FLAGS);
	config->options_deny    = HXmap_init(HXMAPT_DEFAULT, OPT_MAP_FLAGS);
	str_to_optlist(config->options_allow, options_allow);
	str_to_optlist(config->options_require, options_require);
	HXclist_init(&config->volume_list);
}

bool readconfig(const char *file, bool global_conf, struct config *config)
{
	const struct callbackmap *cmp;
	const char *err;
	xmlDoc *doc;
	xmlNode *ptr;

	if ((doc = xmlParseFile(file)) == NULL) {
		l0g("libxml detected a syntax error in %s\n", file);
		return false;
	}
	ptr = xmlDocGetRootElement(doc);
	if (ptr == NULL || xml_strcmp(ptr->name, "pam_mount") != 0) {
		xmlFreeDoc(doc);
		return false;
	}

	config->level = global_conf ? CONTEXT_GLOBAL : CONTEXT_LUSER;
	for (ptr = ptr->children; ptr != NULL; ptr = ptr->next) {
		if (ptr->type != XML_ELEMENT_NODE)
			continue;
		for (cmp = cf_tags; cmp->name != NULL; ++cmp)
			if (xml_strcmp(ptr->name, cmp->name) == 0) {
				err = (*cmp->func)(ptr, config, cmp->cmd);
				if (err != NULL)
					l0g("%s\n", err);
				break;
			}
	}

	xmlFreeDoc(doc);
	return true;
}

//-----------------------------------------------------------------------------
/**
 * fstab_value -
 * @volume:	path to volume
 * @field:	-
 *
 * Search for @volume in /etc/fstab and if it is found, copy the @field'th
 * field and return it. Returns %NULL on error.
 */
static char *fstab_value(const char *volume, const enum fstab_field field)
{
	char *val;
#if defined(__linux__)
	struct mntent *fstab_record;
	FILE *fstab;

	if ((fstab = setmntent("/etc/fstab", "r")) == NULL) {
		l0g("could not open fstab\n");
		return NULL;
	}

	for (fstab_record = getmntent(fstab);
	    fstab_record != NULL &&
	    strcmp(fstab_record->mnt_fsname, volume) != 0;
	    fstab_record = getmntent(fstab))
		/* skip fstab entries until a match is found */;

	if (fstab_record == NULL) {
		l0g("could not get %dth fstab field for %s\n", field, volume);
		return NULL;
	}

	switch (field) {
		case FSTAB_VOLUME:
			val = fstab_record->mnt_fsname;
			break;
		case FSTAB_MNTPT:
			val = fstab_record->mnt_dir;
			break;
		case FSTAB_FSTYPE:
			val = fstab_record->mnt_type;
			break;
		case FSTAB_OPTS:
			val = fstab_record->mnt_opts;
			break;
		default:
			l0g("field of %d invalid\n", field);
			return NULL;
	}
#elif defined (__FreeBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
	struct fstab *fstab_record;

	if (!setfsent()) {
		l0g("could not open fstab\n");
		return NULL;
	}
	if ((fstab_record = getfsspec(volume)) == NULL) {
		l0g("could not get %dth fstab field for %s\n", field, volume);
		return NULL;
	}

	switch (field) {
		case FSTAB_VOLUME:
			val = fstab_record->fs_spec;
			break;
		case FSTAB_MNTPT:
			val = fstab_record->fs_file;
			break;
		case FSTAB_FSTYPE:
			val = fstab_record->fs_vfstype;
			break;
		case FSTAB_OPTS:
			val = fstab_record->fs_mntops;
			break;
		default:
			l0g("field of %d invalid\n", field);
			return NULL;
	}
#else
	l0g("reading fstab not implemented on arch.\n");
	return NULL;
#endif

	val = xstrdup(val);
#if defined(__linux__)
	endmntent(fstab);
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
	endfsent();
#endif
	return val;
}

/**
 * get_next_argument -
 * @sptr:	pointer to pointer to writable string
 *
 * Unescapes the next argument from @*sptr and writes it into @*sptr,
 * which is returned. (In-place unescape)
 */
static inline char *get_next_argument(char **sptr)
{
	char *i = *sptr, *o = i, *ret = i;
	char quot = '\0';

	if (*i == '\0')
		return NULL;
	while (HX_isspace(*i))
		++i;

	while (*i != '\0') {
		if (quot == '\0') {
			if (HX_isspace(*i)) {
				++i;
				break;
			}
			switch (*i) {
				case '"':
				case '\'':
					quot = *i++;
					continue;
				case '\\':
					if (*++i != '\0')
						*o++ = *i;
					continue;
				default:
					*o++ = *i++;
					continue;
			}
			break;
		}
		if (*i == quot) {
			quot = 0;
			++i;
			continue;
		} else if (*i == '\\') {
			*o++ = *++i;
			++i;
			continue;
		}
		*o++ = *i++;
	}
	*o++  = '\0';
	*sptr = i;
	return ret;
}

static inline bool parse_bool(const char *s)
{
	return strcasecmp(s, "yes") == 0 || strcasecmp(s, "on") == 0 ||
	       strcasecmp(s, "true") == 0 || strcmp(s, "1") == 0;
}

static inline bool parse_bool_f(char *s)
{
	bool ret;
	if (s == NULL)
		return false;
	ret = parse_bool(s);
	free(s);
	return ret;
}

/**
 * user_in_sgrp -
 * @user:	user to check
 * @grp:	group name
 *
 * Checks whether @user has @grp as one its _secondary_ groups. Returns 0 if
 * no match was found, positive non-zero on success or negative non-zero on
 * failure.
 */
static bool user_in_sgrp(const char *user, const char *grp, bool icase)
{
	struct group *gent;
	const char *const *wp;

	if ((gent = getgrnam(grp)) == NULL) {
		if (errno != 0)
			w4rn("getgrnam(\"%s\") failed: %s\n",
			     grp, strerror(errno));
		return false;
	}

	wp = const_cast2(const char *const *, gent->gr_mem);
	while (wp != NULL && *wp != NULL) {
		if (strcmp(*wp, user) == 0 ||
		    (icase && strcasecmp(*wp, user) == 0))
			return true;
		++wp;
	}

	return false;
}

//-----------------------------------------------------------------------------
static const char *rc_command(xmlNode *node, struct config *config,
    unsigned int cmdnr)
{
	struct HXdeque *this_cmd;
	char *arg, *wp;

	if (config->level != CONTEXT_GLOBAL)
		return "Tried to set command from user config: "
		       "not permitted\n";
	if ((node = node->children) == NULL)
		return NULL;

	/*
	 * If the command was previously defined, delete the first node. The
	 * stored pointer is returned and we free that. Since the other
	 * pointers are not an allocation head, we only free their nodes.
	 * List has zero elements afterwards.
	 */
	if ((this_cmd = config->command[cmdnr]) != NULL &&
	    this_cmd->items > 0) {
		free(HXdeque_del(this_cmd->first));
		HXdeque_free(this_cmd);
		this_cmd = NULL;
	}
	if (this_cmd == NULL)
		this_cmd = config->command[cmdnr] = HXdeque_init();

	for (; node != NULL; node = node->next) {
		if (node->type != XML_TEXT_NODE)
			continue;

		wp = xstrdup(signed_cast(const char *, node->content));
		while ((arg = get_next_argument(&wp)) != NULL)
			/*
			 * The copy taken with strdup() is not freed in this
			 * function, because it is used soon. 
			 * @config->command[command][0] will be the pointer to
			 * the block to free later.
			 */
			HXdeque_push(this_cmd, arg);

		/* No hassle to support comment-split tags. */
		break;
	}
	return NULL;
}

static const char *rc_debug(xmlNode *node, struct config *config,
    unsigned int cmd)
{
	char *s;
	if ((s = xml_getprop(node, "enable")) != NULL)
		Debug = config->debug = strtoul(s, NULL, 0);

		pmtlog_path[PMTLOG_DBG][PMTLOG_SYSLOG] =
		pmtlog_path[PMTLOG_DBG][PMTLOG_STDERR] =
			Debug;
	free(s);
	return NULL;
}

static const char *rc_logout(xmlNode *node, struct config *config,
    unsigned int command)
{
	char *tmp;

	if ((tmp = xml_getprop(node, "wait")) != NULL) {
		config->sig_wait = strtoul(tmp, NULL, 0);
		free(tmp);
	}
	config->sig_hup  = parse_bool_f(xml_getprop(node, "hup"));
	config->sig_term = parse_bool_f(xml_getprop(node, "term"));
	config->sig_kill = parse_bool_f(xml_getprop(node, "kill"));
	return NULL;
}

static const char *rc_luserconf(xmlNode *node, struct config *config,
    unsigned int command)
{
	struct passwd *pent;
	char *s;

	if (config->level != CONTEXT_GLOBAL)
		return "Tried to set <luserconf> from user config: "
		       "meaningless";
	if ((pent = getpwnam(config->user)) == NULL)
		return "Could not get password entry";
	if ((s = xml_getprop(node, "name")) == NULL)
		return "<luserconf> is missing name= attribute";
	HXmc_free(config->luserconf);
	config->luserconf = HXmc_strinit(pent->pw_dir);
	HXmc_strcat(&config->luserconf, "/");
	HXmc_strcat(&config->luserconf, s);
	w4rn("path to luserconf set to %s\n", config->luserconf);
	free(s);
	return NULL;
}

static const char *rc_mkmountpoint(xmlNode *node, struct config *config,
    unsigned int command)
{
	char *s;
	if ((s = xml_getprop(node, "enable")) != NULL)
		config->mkmntpoint = strtol(s, NULL, 0);
	free(s);
	if ((s = xml_getprop(node, "remove")) != NULL)
		config->rmdir_mntpt = parse_bool(s);
	free(s);
	return NULL;
}

static const char *rc_mntoptions(xmlNode *node, struct config *config,
    unsigned int command)
{
	char *options;
	int ret;

	if (config->level != CONTEXT_GLOBAL)
		return "Tried to set <mntoptions allow=...> from user config: "
		       "not permitted";
	if ((options = xml_getprop(node, "allow")) != NULL) {
		if (!config->seen_mntoptions_allow) {
			HXmap_free(config->options_allow);
			config->options_allow =
				HXmap_init(HXMAPT_DEFAULT, OPT_MAP_FLAGS);
			config->seen_mntoptions_allow = true;
		}
		ret = str_to_optlist(config->options_allow, options);
		free(options);
		if (!ret)
			return "Error parsing allowed options";
	}

	if ((options = xml_getprop(node, "deny")) != NULL) {
		ret = str_to_optlist(config->options_deny, options);
		free(options);
		if (!ret)
			return "Error parsing denied options";
	}

	if ((options = xml_getprop(node, "require")) != NULL) {
		/*
		 * On the first sight of "require" in the config file, the
		 * built-in default shall be overridden, but multiple
		 * "require"s shall be cumulative.
		 */
		if (!config->seen_mntoptions_require) {
			HXmap_free(config->options_require);
			config->options_require =
				HXmap_init(HXMAPT_DEFAULT, OPT_MAP_FLAGS);
			config->seen_mntoptions_require = true;
		}
		ret = str_to_optlist(config->options_require, options);
		free(options);
		if (!ret)
			return "Error parsing required options";
	}	

	return NULL;
}

static const char *rc_string(xmlNode *node, struct config *config,
    unsigned int command)
{
	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_TEXT_NODE)
			continue;
		switch (command) {
			case CMDA_AUTHPW:
				free(config->msg_authpw);
				config->msg_authpw = xstrdup(signed_cast(const char *, node->content));
				break;
			case CMDA_SESSIONPW:
				free(config->msg_sessionpw);
				config->msg_sessionpw = xstrdup(signed_cast(const char *, node->content));
				break;
			case CMDA_PATH:
				free(config->path);
				config->path = xstrdup(signed_cast(const char *, node->content));
				break;
		}
		break;
	}
	return NULL;
}

/**
 * rc_volume_cond_and - handle <and> element
 * @pwd:	user logging in
 * @node: 	XML <and> node
 *
 * Handle an <and> XML node, by processing all elements within it and ANDing
 * them together. Returns negative on error.
 */
static int rc_volume_cond_and(const struct passwd *pwd, xmlNode *node)
{
	unsigned int count = 0;
	int ret;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;
		ret = rc_volume_cond_ext(pwd, node);
		if (ret < 0)
			return ret;
		else if (ret == 0)
			return false;
		++count;
	}

	if (count > 0)
		/*
		 * If there was any non-matching element, we would have
		 * already returned above.
		 */
		return true;

	l0g("config: <and> does not have any child elements\n");
	return -1;
}

/**
 * rc_volume_cond_or - handle <or> element
 * @pwd:	user logging in
 * @node:	XML <or> node
 *
 * Handle an <or> XML node, by processing all elements within it and ORing
 * them together. On error, returns -1.
 */
static int rc_volume_cond_or(const struct passwd *pwd, xmlNode *node)
{
	unsigned int count = 0;
	int ret;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;
		ret = rc_volume_cond_ext(pwd, node);
		if (ret < 0)
			return ret;
		else if (ret > 0)
			return true;
		++count;
	}

	if (count > 0)
		return false;

	l0g("config: <and> does not have any child elements\n");
	return -1;
}

/**
 * rc_volume_cond_xor - handle <xor> element
 * @pwd:	user logging in
 * @node:	XML <xor> node
 *
 * Handle an <xor> XML node, by processing the two elements within it and
 * XORin them together. Exactly two elements must be provided, otherwise
 * the function fails with -1.
 */
static int rc_volume_cond_xor(const struct passwd *pwd, xmlNode *node)
{
	unsigned int count = 0;
	int ret[2];

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (count >= 2)
			goto out;
		ret[count] = rc_volume_cond_ext(pwd, node);
		if (ret[count] < 0)
			return ret[count];
		++count;
	}

	if (count == 2)
		return ret[0] ^ ret[1];
 out:
	l0g("config: <xor> must have exactly two child elements\n");
	return -1;
}

/**
 * rc_volume_cond_not - handle <not> element
 * @pwd:	user logging in
 * @node:	XML <not> node
 *
 * Handle an <not> XML node, by processing the single elements within it and
 * negating it. Exactly one elements must be provided, otherwise the
 * function fails with -1.
 */
static int rc_volume_cond_not(const struct passwd *pwd, xmlNode *node)
{
	unsigned int count = 0;
	bool ret = true;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (count++ > 0)
			goto out;
		ret = rc_volume_cond_ext(pwd, node);
		if (ret < 0)
			return ret;
		ret = !ret;
	}

	if (count == 1)
		return ret;
 out:
	l0g("config: <not> may only have one child element\n");
	return -1;
}

/**
 * rc_volume_cond_user - handle <user> element
 * @pwd:	user logging in
 * @node:	XML <user> node
 */
static int rc_volume_cond_user(const struct passwd *pwd, xmlNode *node)
{
	xmlNode *parent = node;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_TEXT_NODE)
			continue;
		if (parse_bool_f(xml_getprop(parent, "icase")))
			return strcasecmp(signed_cast(const char *,
			       node->content), pwd->pw_name) == 0;
		else
			return xml_strcmp(node->content, pwd->pw_name) == 0;
	}

	return false;
}

static int __rc_volume_cond_id(const char *s, unsigned int id)
{
	unsigned int id_start, id_end;
	char *delim;

	id_start = id_end = strtoul(s, &delim, 0);
	if (*delim == '\0')
		return id_start == id;
	if (*delim != '-' || *++delim == '\0')
		return -1;
	id_end = strtoul(delim, &delim, 0);
	if (*delim != '\0')
		return -1;
	return id_start <= id && id <= id_end;
}

/**
 * rc_volume_cond_uid - handle <uid> element
 * @pwd:	user logging in
 * @node:	XML <uid> node
 */
static int rc_volume_cond_uid(const struct passwd *pwd, xmlNode *node)
{
	int ret;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_TEXT_NODE)
			continue;
		ret = __rc_volume_cond_id(signed_cast(const char *,
		      node->content), pwd->pw_uid);
		return ret;
	}

	l0g("config: empty or invalid content for <%s>\n", "uid");
	return -1;
}

/**
 * rc_volume_cond_gid - handle <gid> element
 * @pwd:	user logging in
 * @node:	XML <uid> node
 */
static int rc_volume_cond_gid(const struct passwd *pwd, xmlNode *node)
{
	int ret;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_TEXT_NODE)
			continue;
		ret = __rc_volume_cond_id(signed_cast(const char *,
		      node->content), pwd->pw_gid);
		return ret;
	}

	l0g("config: empty or invalid content for <%s>\n", "gid");
	return -1;
}

static int __rc_volume_cond_pgrp(const char *group, unsigned int gid,
    bool icase)
{
	const struct group *grp;

	errno = 0;
	grp   = getgrgid(gid);
	if (grp == NULL) {
		if (errno == 0)
			return 0; /* just not found */

		w4rn("getgrgid(%u) failed: %s\n", gid, strerror(errno));
		return -1;
	}

	if (icase)
		return strcasecmp(group, grp->gr_name) == 0;
	else
		return strcmp(group, grp->gr_name) == 0;
}

/**
 * rc_volume_cond_pgrp - handle <pgrp> element
 * @pwd:	user logging in
 * @node:	XML <pgrp> node (actually also <sgrp>)
 */
static int rc_volume_cond_pgrp(const struct passwd *pwd, xmlNode *node)
{
	xmlNode *parent = node;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_TEXT_NODE)
			continue;

		return __rc_volume_cond_pgrp(
		       signed_cast(const char *, node->content), pwd->pw_gid,
		       parse_bool_f(xml_getprop(parent, "icase")));
	}

	l0g("config: empty or invalid content for <%s>\n", "pgrp");
	return -1;
}

/**
 * rc_volume_cond_sgrp - handle <sgrp> element
 * @pwd:	user logging in
 * @node:	XML <sgrp> node
 */
static int rc_volume_cond_sgrp(const struct passwd *pwd, xmlNode *node)
{
	const struct group *grp;
	xmlNode *parent = node;
	int ret;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_TEXT_NODE)
			continue;

		if ((grp = getgrgid(pwd->pw_gid)) == NULL) {
			if (errno == 0)
				return 0;
			w4rn("getgrgid(%ld) failed: %s\n",
			     static_cast(long, pwd->pw_gid), strerror(errno));
			return -1;
		}

		ret = rc_volume_cond_pgrp(pwd, parent);
		if (ret < 0 || ret > 0)
			return ret;
		return user_in_sgrp(pwd->pw_name,
		       signed_cast(const char *, node->content),
		       parse_bool_f(xml_getprop(parent, "icase")));
	}

	l0g("config: empty or invalid content for <%s>\n", "sgrp");
	return -1;
}

/**
 * rc_volume_cond_ext - interpret extended user control elements
 * @pwd:	user logging in
 * @node:	XML node to operate on
 */
static int rc_volume_cond_ext(const struct passwd *pwd, xmlNode *node)
{
	if (xml_strcmp(node->name, "and") == 0)
		return rc_volume_cond_and(pwd, node);
	else if (xml_strcmp(node->name, "or") == 0)
		return rc_volume_cond_or(pwd, node);
	else if (xml_strcmp(node->name, "xor") == 0)
		return rc_volume_cond_xor(pwd, node);
	else if (xml_strcmp(node->name, "not") == 0)
		return rc_volume_cond_not(pwd, node);
	else if (xml_strcmp(node->name, "user") == 0)
		return rc_volume_cond_user(pwd, node);
	else if (xml_strcmp(node->name, "uid") == 0)
		return rc_volume_cond_uid(pwd, node);
	else if (xml_strcmp(node->name, "gid") == 0)
		return rc_volume_cond_gid(pwd, node);
	else if (xml_strcmp(node->name, "pgrp") == 0)
		return rc_volume_cond_pgrp(pwd, node);
	else if (xml_strcmp(node->name, "sgrp") == 0)
		return rc_volume_cond_sgrp(pwd, node);

	l0g("config: unknown element <%s>\n", node->name);
	return -1;
}

/**
 * rc_volume_cond_simple - interpret simple user control elements
 * @pwd:	user logging in
 * @node:	XML <volume> node
 */
static int rc_volume_cond_simple(const struct passwd *pwd, xmlNode *node)
{
	char *user   = xml_getprop(node, "user");
	char *invert = xml_getprop(node, "invert");
	char *uid    = xml_getprop(node, "uid");
	char *gid    = xml_getprop(node, "gid");
	char *pgrp   = xml_getprop(node, "pgrp");
	char *sgrp   = xml_getprop(node, "sgrp");
	bool for_me  = true;
	int ret      = true;

	if (user == NULL && invert == NULL && uid == NULL && gid == NULL &&
	    pgrp == NULL && sgrp == NULL)
		return -1;

	if (user != NULL) {
		if (strcmp(user, "*") != 0)
			for_me &= strcmp(pwd->pw_name, user) == 0;
		else if (pwd->pw_uid == 0 || strcmp(pwd->pw_name, "root") == 0)
			/* The wildcard never matches root */
			for_me &= false;
	} else if (pwd->pw_uid == 0 || strcmp(pwd->pw_name, "root") == 0) {
		/* No user field at all generally implies the wildcard */
		for_me &= false;
	}
	if (uid != NULL) {
		ret = __rc_volume_cond_id(uid, pwd->pw_uid);
		if (ret < 0)
			goto out;
		for_me &= ret;
	}
	if (gid != NULL) {
		ret = __rc_volume_cond_id(gid, pwd->pw_gid);
		if (ret < 0)
			goto out;
		for_me &= ret;
	}
	if (pgrp != NULL) {
		ret = __rc_volume_cond_pgrp(pgrp, pwd->pw_gid, false);
		if (ret < 0)
			goto out;
		for_me &= ret;
	}
	if (sgrp != NULL) {
		bool ret2 = __rc_volume_cond_pgrp(sgrp, pwd->pw_gid, false);
		if (ret < 0)
			goto out;
		ret = user_in_sgrp(pwd->pw_name, sgrp, false);
		if (ret < 0)
			goto out;
		for_me &= ret || ret2;
	}
	if (invert != NULL) {
		l0g("The \"invert\" attribute is deprecated, support will "
		    "be removed in next version.\n");
		if (strtoul(invert, NULL, 0))
			for_me = !for_me;
	}

 out:
	free(user);
	free(invert);
	free(uid);
	free(gid);
	free(pgrp);
	free(sgrp);
	if (ret < 0)
		return ret;
	return for_me;
}

/**
 * rc_volume_cond - check if volume applies to user
 * @node:	XML <volume> node
 */
static int rc_volume_cond(const char *user, xmlNode *node)
{
	struct passwd *pwd_ent;
	int ret;

	if ((pwd_ent = getpwnam(user)) == NULL) {
		if (errno == 0)
			return 0;
		l0g("getpwnam: %s\n", strerror(errno));
		return -1;
	}

	ret = rc_volume_cond_simple(pwd_ent, node);
	if (ret < 0 && node->children != NULL) {
		/* When no attributes, but elements... */
		ret = rc_volume_cond_and(pwd_ent, node);
		if (ret < 0)
			return -1;
		else if (ret == 0)
			return false;
	} else if (ret == 0) {
		/* Attributes but (hopefully) no elements. */
		if (node->children != NULL) {
			l0g("You cannot have both simple and extended user control\n");
			return -1;
		}
		return false;
	}

	return true;
}

static const char *rc_volume(xmlNode *node, struct config *config,
    unsigned int command)
{
	const char *err;
	struct vol *vpt;
	unsigned int i;
	char *tmp;

	if (rc_volume_cond(config->user, node) <= 0)
		return NULL;

	vpt = calloc(1, sizeof(struct vol));
	if (vpt == NULL)
		return strerror(errno);

	HXlist_init(&vpt->list);
	HXclist_push(&config->volume_list, &vpt->list);

	vpt->globalconf = config->level == CONTEXT_GLOBAL;
	vpt->user = config->user;
	vpt->type = CMD_LCLMOUNT;
	HXclist_init(&vpt->options);

	/* Eyeball ssh setting */
	if ((tmp = xml_getprop(node, "ssh")) != NULL)
		vpt->uses_ssh = parse_bool_f(tmp);

	/* Filesystem type */
	if ((tmp = xml_getprop(node, "fstype")) != NULL) {
		free(vpt->fstype);
		vpt->fstype = tmp;

		for (i = 0; default_command[i].type != -1; ++i) {
			const struct pmt_command *c = &default_command[i];
			if (c->fs != NULL && strcasecmp(tmp, c->fs) == 0) {
				vpt->type = c->type;
				break;
			}
		}
	} else {
		vpt->fstype = xstrdup("auto");
	}

	if ((tmp = xml_getprop(node, "noroot")) != NULL) {
		vpt->noroot = parse_bool_f(tmp);
	} else if (vpt->fstype != NULL) {
		/* Figure out whether we want to act as user. */
		vpt->noroot =
			strcmp(vpt->fstype, "fuse") == 0 ||
			strcmp(vpt->fstype, "encfs13") == 0;
	}

	/* Source location */
	if ((tmp = xml_getprop(node, "server")) != NULL) {
		free(vpt->server);
		vpt->server = tmp;
	}
	if ((tmp = xml_getprop(node, "path")) != NULL) {
		free(vpt->volume);
		vpt->volume = tmp;
	}

	/* Destination */
	if ((tmp = xml_getprop(node, "mountpoint")) != NULL) {
		free(vpt->mountpoint);
		vpt->mountpoint = tmp;
	} else {
		free(vpt->mountpoint);
		vpt->mountpoint = fstab_value(vpt->volume, FSTAB_MNTPT);
		if (vpt->mountpoint == NULL) {
			err = "could not determine mountpoint";
			goto out;
		}
		vpt->use_fstab = 1;
	}

	/* Options */
	if ((tmp = xml_getprop(node, "options")) == NULL) {
		/*
		 * Three options: field defined, field is '-' and fstab should
		 * be used (when no mount point was provided either) or field
		 * is '-' and this means no options.
		 */
		if (vpt->use_fstab) {
			char *options = fstab_value(vpt->volume, FSTAB_OPTS);
			if (options == NULL) {
				err = "could not determine options";
				goto out;
			}
			if (!str_to_optkv(&vpt->options, options)) {
				err = "error parsing mount options";
				goto out;
			}
			free(options);
		}
	} else if (!str_to_optkv(&vpt->options, tmp)) {
		free(tmp);
		err = "error parsing mount options";
		goto out;
	} else {
		free(tmp);
	}

	/* Filesystem key */
	if ((tmp = xml_getprop(node, "cipher")) != NULL) {
		free(vpt->cipher);
		vpt->cipher = tmp;
	}
	if ((tmp = xml_getprop(node, "fskeypath")) != NULL) {
		free(vpt->fs_key_path);
		vpt->fs_key_path = tmp;
	}
	if ((tmp = xml_getprop(node, "fskeycipher")) != NULL) {
		free(vpt->fs_key_cipher);
		vpt->fs_key_cipher = tmp;
	}
	if ((tmp = xml_getprop(node, "fskeyhash")) != NULL) {
		free(vpt->fs_key_hash);
		vpt->fs_key_hash = tmp;
	} else if (vpt->fs_key_path != NULL) {
		l0g("Volume %s: consider specifying the fskeyhash\n",
		    (vpt->volume != NULL) ? vpt->volume : "(null)");
		vpt->fs_key_hash = HX_strdup("md5");
	}

	if (fstype_nodev(vpt->fstype) == 1 && vpt->volume == NULL)
		vpt->volume = xstrdup("none");

	return NULL;

 out:
	HXclist_del(&config->volume_list, &vpt->list);
	volume_free(vpt);
	return err;
}

//-----------------------------------------------------------------------------
static const struct pmt_command default_command[] = {
	{CMD_SMBMOUNT,   "smbfs", {"smbmount", "//%(SERVER)/%(VOLUME)", "%(MNTPT)", "-o", "username=%(USER),uid=%(USERUID),gid=%(USERGID)%(if %(OPTIONS),\",%(OPTIONS)\")", NULL}},
	{CMD_SMBUMOUNT,  "smbfs", {"smbumount", "%(MNTPT)", NULL}},
	{CMD_CIFSMOUNT,   "cifs", {"mount", "-t", "cifs", "//%(SERVER)/%(VOLUME)", "%(MNTPT)", "-o", "user=%(USER),uid=%(USERUID),gid=%(USERGID)%(if %(OPTIONS),\",%(OPTIONS)\")", NULL}},
	{CMD_NCPMOUNT,   "ncpfs", {"ncpmount", "%(SERVER)/%(USER)", "%(MNTPT)", "-o", "pass-fd=0,volume=%(VOLUME)%(if %(OPTIONS),\",%(OPTIONS)\")", NULL}},
	{CMD_NCPUMOUNT,  "ncpfs", {"ncpumount", "%(MNTPT)", NULL}},
	{CMD_FUSEMOUNT,   "fuse", {"mount.fuse", "%(VOLUME)", "%(MNTPT)", "%(if %(OPTIONS),-o%(OPTIONS))", NULL}},
	{CMD_FUSEUMOUNT, "fuse",  {"fusermount", "-u", "%(MNTPT)", NULL}},
	/* Do not use LCLMOUNT to avoid calling fsck */
	{CMD_NFSMOUNT,    "nfs",   {"mount", "%(if %(OPTIONS),-o%(OPTIONS))", "-t%(FSTYPE)", "%(SERVER):%(VOLUME)", "%(MNTPT)", NULL}},
	{CMD_NFSMOUNT,    "nfs4"},
	{CMD_LCLMOUNT,    NULL,    {"mount", "-p0", "%(if %(OPTIONS),-o%(OPTIONS))", "-t%(FSTYPE)", "%(VOLUME)", "%(MNTPT)", NULL}},
	{CMD_CRYPTMOUNT,  "crypt", {"mount", "-t", "crypt", "%(if %(CIPHER),-ocipher=%(CIPHER))", "%(if %(FSKEYCIPHER),-ofsk_cipher=%(FSKEYCIPHER))", "%(if %(FSKEYHASH),-ofsk_hash=%(FSKEYHASH))", "%(if %(FSKEYPATH),-okeyfile=%(FSKEYPATH))", "%(if %(OPTIONS),-o%(OPTIONS))", "%(VOLUME)", "%(MNTPT)", NULL}},
	{CMD_CRYPTUMOUNT, "crypt", {"umount", "%(MNTPT)", NULL}},
	{CMD_UMOUNT,     NULL,     {"umount", "%(MNTPT)", NULL}},
	{CMD_FSCK,       NULL,     {"fsck", "-p", "%(FSCKTARGET)", NULL}},
	{CMD_PMVARRUN,   NULL,     {"pmvarrun", "-u", "%(USER)", "-o", "%(OPERATION)", NULL}},
	{CMD_FD0SSH,      NULL,    {"pmt-fd0ssh", NULL}},
	{CMD_OFL,        NULL,     {"pmt-ofl", "-k%(SIGNAL)", "%(MNTPT)", NULL}},
	{-1},
};

static const struct callbackmap cf_tags[] = {
	{"cifsmount",       rc_command,             CMD_CIFSMOUNT},
	{"cryptmount",      rc_command,             CMD_CRYPTMOUNT},
	{"cryptumount",     rc_command,             CMD_CRYPTUMOUNT},
	{"debug",           rc_debug,               CMD_NONE},
	{"fd0ssh",          rc_command,             CMD_FD0SSH},
	{"fsck",            rc_command,             CMD_FSCK},
	{"fusemount",       rc_command,             CMD_FUSEMOUNT},
	{"fuseumount",      rc_command,             CMD_FUSEUMOUNT},
	{"lclmount",        rc_command,             CMD_LCLMOUNT},
	{"logout",          rc_logout,              CMD_NONE},
	{"luserconf",       rc_luserconf,           CMD_NONE},
	{"mkmountpoint",    rc_mkmountpoint,        CMD_NONE},
	{"mntoptions",      rc_mntoptions,          CMD_NONE},
	{"msg-authpw",      rc_string,              CMDA_AUTHPW},
	{"msg-sessionpw",   rc_string,              CMDA_SESSIONPW},
	{"nfsmount",        rc_command,             CMD_NFSMOUNT},
	{"ncpmount",        rc_command,             CMD_NCPMOUNT},
	{"ncpumount",       rc_command,             CMD_NCPUMOUNT},
	{"ofl",             rc_command,             CMD_OFL},
	{"path",            rc_string,              CMDA_PATH},
	{"pmvarrun",        rc_command,             CMD_PMVARRUN},
	{"smbmount",        rc_command,             CMD_SMBMOUNT},
	{"smbumount",       rc_command,             CMD_SMBUMOUNT},
	{"umount",          rc_command,             CMD_UMOUNT},
	{"volume",          rc_volume,              CMD_NONE},
	{NULL},
};
