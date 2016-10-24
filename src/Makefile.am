# -*- Makefile -*-

AM_CPPFLAGS = ${regular_CPPFLAGS} -DRUNDIR=\"${rundir}\" \
		${libHX_CFLAGS} ${libcrypto_CFLAGS} ${libcryptsetup_CFLAGS} \
		${libmount_CFLAGS} ${libpcre_CFLAGS} ${libxml_CFLAGS}
AM_CFLAGS = ${regular_CFLAGS} ${GCC_FVISIBILITY_HIDDEN}

moduledir		= @PAM_MODDIR@
module_LTLIBRARIES	= pam_mount.la
sbin_PROGRAMS		= pmvarrun
if HAVE_LIBCRYPTSETUP
sbin_PROGRAMS		+= pmt-ehd
endif
ssbin_PROGRAMS		= mount.crypt
noinst_PROGRAMS		= autoloop
noinst_SCRIPTS 		= umount.crypt

lib_LTLIBRARIES		= libcryptmount.la
noinst_LTLIBRARIES	= libpmt_mtab.la

#
# libcryptmount
#
libcryptmount_la_SOURCES = crypto.c log.c loop.c loop-linux.c
libcryptmount_la_LDFLAGS = -Wl,--version-script=${srcdir}/libcryptmount.map \
                           -version-info 0:0:0
libcryptmount_la_LIBADD = ${libHX_LIBS} ${libcrypto_LIBS}
libcryptmount_la_DEPENDENCIES = ${srcdir}/libcryptmount.map

if HAVE_LIBCRYPTSETUP
libcryptmount_la_SOURCES += crypto-dmc.c
libcryptmount_la_LIBADD += ${libcryptsetup_LIBS}
endif
if HAVE_CGD
libcryptmount_la_SOURCES += crypto-cgd.c
endif
if HAVE_MDIO
libcryptmount_la_SOURCES += loop-mdvn.c
endif
if HAVE_VND
libcryptmount_la_SOURCES += loop-vnd.c
endif

include_HEADERS = libcryptmount.h

#
# libpmt_mtab
#
libpmt_mtab_la_SOURCES = misc.c mtab.c
libpmt_mtab_la_CFLAGS  = ${AM_CFLAGS}
libpmt_mtab_la_LIBADD  = ${libHX_LIBS}

#
# pam_mount.so
#
pam_mount_la_SOURCES	= misc.c mount.c pam_mount.c \
			  rdconf1.c rdconf2.c spawn.c
pam_mount_la_CFLAGS	= ${AM_CFLAGS}
pam_mount_la_LIBADD	= libcryptmount.la -lpam ${libHX_LIBS} \
			  ${libmount_LIBS} ${libpcre_LIBS} ${libxml_LIBS}
pam_mount_la_LDFLAGS	= -module -avoid-version

#
# test tools
#
autoloop_SOURCES	= autoloop.c
autoloop_LDADD		= libcryptmount.la ${libHX_LIBS}

#
# mount helpers
#
mount_crypt_SOURCES	= mtcrypt.c spawn.c
mount_crypt_LDADD	= libcryptmount.la libpmt_mtab.la ${libHX_LIBS}

pmt_ehd_SOURCES		= ehd.c bdev.c misc.c spawn.c
pmt_ehd_LDADD		= libcryptmount.la ${libHX_LIBS} ${libcryptsetup_LIBS}

#
# runtime helpers
#
pmvarrun_SOURCES = pmvarrun.c
pmvarrun_LDADD   = libcryptmount.la ${libHX_LIBS}

EXTRA_DIST = cmt-internal.h libcryptmount.h pam_mount.h libcryptmount.map

umount.crypt${EXEEXT}: mount.crypt${EXEEXT}
	-${LN_S} -f $^ $@;

if !KEEP_LA
install-data-hook:
	rm -f $(DESTDIR)$(moduledir)/pam_mount.la;
endif

#
#	udev/libvolume_id detects LUKS volumes as "crypto_LUKS", while
#	blkid/libblkid detects them as "crypt_LUKS".
#	Talking to the maintainers, crypto_LUKS is what was wanted.
#	Providing symlinks for compat...
#
mtcrypt_symlinks = \
	umount.crypt${EXEEXT} \
	mount.crypto_LUKS${EXEEXT} umount.crypto_LUKS${EXEEXT} \
	mount.crypt_LUKS${EXEEXT} umount.crypt_LUKS${EXEEXT}

install-exec-hook:
	${MKDIR_P} ${DESTDIR}${ssbindir};
	-for i in ${mtcrypt_symlinks}; do \
		${LN_S} -f mount.crypt${EXEEXT} "${DESTDIR}${ssbindir}/$$i"; \
	done;

uninstall-hook:
	-for i in ${mtcrypt_symlinks}; do \
		rm "${DESTDIR}${ssbindir}/$$i"; \
	done;
