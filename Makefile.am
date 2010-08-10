# -*- Makefile -*-

ACLOCAL_AMFLAGS  = -I m4
SUBDIRS = config doc src

install-data-hook:
	${MKDIR_P} ${DESTDIR}${localstatedir}/run/pam_mount;

tmpdir := $(shell mktemp -dtu)
packer  = xz
packext = .tar.xz

.PHONY: tarball
tarball:
# do not use mkdir_p here.
	mkdir ${tmpdir}
	pushd ${top_srcdir} && git archive --prefix=${PACKAGE_NAME}-${PACKAGE_VERSION}/ HEAD | tar -C ${tmpdir} -x && popd;
	pushd ${tmpdir}/${PACKAGE_NAME}-${PACKAGE_VERSION} && ./autogen.sh && popd;
	tar --use=${packer} -C ${tmpdir} -cf ${PACKAGE_NAME}-${PACKAGE_VERSION}${packext} --owner=root --group=root ${PACKAGE_NAME}-${PACKAGE_VERSION}/;
	rm -Rf ${tmpdir};

dist-hook:
	tar --use=${packer} -cf ${PACKAGE_NAME}-${PACKAGE_VERSION}${packext} --owner=root --group=root ${distdir}

DISTCHECK_CONFIGURE_FLAGS = \
	--with-ssbindir='$${abs_builddir}/ssbin' \
	--with-slibdir='$${abs_builddir}/slib' \
	--enable-la

DISTCLEANFILES = ${PACKAGE_NAME}-${PACKAGE_VERSION}${packext}
EXTRA_DIST = autogen.sh dist/pam_mount.spec LICENSE.GPL2 LICENSE.GPL3 \
	LICENSE.LGPL2 LICENSE.LGPL3
