#
#	Copyright (C) 2002 W. Michael Petullo <mike@flyn.org>
#	Copyright © Jan Engelhardt, 2005 - 2010
#
#	This file is part of pam_mount; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; either version 2 of the License, or
#	(at your option) any later version.
#
AC_INIT([pam_mount], [2.5])
PACKAGE_RELDATE="2010-08-10"
AC_PREREQ([2.59])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_INSTALL
AM_INIT_AUTOMAKE([-Wall dist-bzip2 no-dist-gzip foreign subdir-objects])
AC_PROG_CC
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AM_PROG_LIBTOOL
AC_PROG_LN_S

AC_ARG_WITH([slibdir], AS_HELP_STRING([--with-slibdir=PATH],
	[Path to the super lib directory [[/lib]]]),
	[slibdir="$withval"], [slibdir="/lib"])
AC_SUBST(slibdir)
AC_ARG_WITH([ssbindir], AS_HELP_STRING([--with-ssbindir=PATH],
	[Path to the super sbin directory [[/sbin]]]),
	[ssbindir="$withval"], [ssbindir="/sbin"])
AC_SUBST(ssbindir)
AC_ARG_WITH([dtd], AS_HELP_STRING([--with-dtd],
	[Install XML DTD file]),
	[with_dtd=true], [with_dtd=false])
AC_ARG_WITH([selinux], AS_HELP_STRING([--with-selinux],
	[Install selinux files]),
	[with_selinux=true], [with_selinux=false])
AC_ARG_ENABLE([la], AS_HELP_STRING([--enable-la],
	[Install .la file (used for distcheck)]),
	[keep_la=true], [keep_la=false])
AM_CONDITIONAL([KEEP_LA], [test "x$keep_la" = "xtrue"])
AM_CONDITIONAL([SELINUX], [test "x$with_selinux" = "xtrue"])
AM_CONDITIONAL([WITH_DTD], [test "x$with_dtd" = "xtrue"])

CHECK_GCC_FVISIBILITY

regular_CFLAGS="-D_FILE_OFFSET_BITS=64 \
	-D_REENTRANT -Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-Wformat=2 -pipe"
AC_SUBST([regular_CFLAGS])

AC_CHECK_HEADERS([linux/fs.h linux/major.h dev/cgdvar.h dev/vndvar.h])
AC_CHECK_HEADERS([sys/mdioctl.h sys/mount.h sys/statvfs.h])
AC_CHECK_MEMBERS([struct loop_info64.lo_file_name], [], [],
	[#include <linux/loop.h>])
AC_CHECK_FUNCS([getmntent getmntinfo initgroups])
AM_CONDITIONAL([HAVE_CGD], [test "x$ac_cv_header_dev_cgdvar_h" = "xyes"])
AM_CONDITIONAL([HAVE_MDIO], [test "x$ac_cv_header_sys_mdioctl_h" = "xyes"])
AM_CONDITIONAL([HAVE_VND], [test "x$ac_cv_header_dev_vndvar_h" = "xyes"])

PKG_CHECK_MODULES([libHX], [libHX >= 3.4])
PKG_CHECK_MODULES([libxml], [libxml-2.0 >= 2.6])

with_crypto="yes";
AC_ARG_WITH(
	[crypto],
	AS_HELP_STRING([--without-crypto], [Disable use of OpenSSL cryptography]),
	[],
	[with_crypto="no"]
)

with_cryptsetup="yes";
AC_ARG_WITH([cryptsetup],
	AS_HELP_STRING([--without-cryptsetup], [Disable use of libcryptsetup]),
	[],
	[with_cryptsetup="no"]
)

if test "x$with_crypto" = "xyes"; then
	PKG_CHECK_MODULES([libcrypto], [libcrypto >= 0.9.8],
		[AC_DEFINE_UNQUOTED([HAVE_LIBCRYPTO], [1],
			[OpenSSL libcrypto available])])
fi;
AM_CONDITIONAL([HAVE_LIBCRYPTO], [test "x$with_crypto" = xyes])

if test "x$with_cryptsetup" = "xyes"; then
	PKG_CHECK_MODULES([libcryptsetup], [libcryptsetup >= 1.1.2],
		[AC_DEFINE_UNQUOTED([HAVE_LIBCRYPTSETUP], [1],
			[libcryptsetup available])])
fi;
AM_CONDITIONAL([HAVE_LIBCRYPTSETUP], [test "x$with_cryptsetup" = xyes])

AC_CHECK_HEADERS([security/pam_modules.h], [have_pamheader="yes"])
# Mac OS X 10.3 puts PAM headers in /usr/include/pam.
AC_CHECK_HEADERS([pam/pam_modules.h], [have_pamheader="yes"])
if test x"$have_pamheader" != x"yes"; then
	AC_MSG_ERROR([You are missing PAM headers])
fi

case "$host" in
    (*-*-linux*|*-*-openbsd*)
	PAM_MODDIR='${slibdir}/security'
	;;
    (*-*-solaris*|*-*-netbsd*)
	PAM_MODDIR='${libdir}/security';
	;;
    (*-*-darwin*)
	PAM_MODDIR='${libdir}/pam';
	;;
    (*)
	PAM_MODDIR='${libdir}';
	;;
esac
AC_SUBST([PAM_MODDIR])

AC_SUBST([PACKAGE_RELDATE])
AC_CONFIG_FILES([Makefile config/Makefile doc/Makefile src/Makefile])
AC_OUTPUT
