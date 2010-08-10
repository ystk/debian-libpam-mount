# -*- Makefile -*-

man_MANS = pam_mount.8 pam_mount.conf.5
dist_man_MANS = mount.crypt.8 mount.crypt_LUKS.8 mount.crypto_LUKS.8 \
		pmvarrun.8 pmt-ehd.8 \
		pmt-fd0ssh.1 umount.crypt.8 umount.crypt_LUKS.8 \
		umount.crypto_LUKS.8
dist_noinst_DATA = pam_mount.txt
EXTRA_DIST = bugs.txt changelog.txt faq.txt install.txt options.txt todo.txt
CLEANFILES = ${man_MANS}

replcmd = perl -lpe 's/\@''PACKAGE\@/@PACKAGE@/g;s/\@''PACKAGE_VERSION\@/@PACKAGE_VERSION@/g;s/\@''PACKAGE_RELDATE\@/@PACKAGE_RELDATE@/g;'

pam_mount.8: pam_mount.8.in ${top_builddir}/config.status
	${AM_V_GEN}${replcmd} ${srcdir}/pam_mount.8.in >pam_mount.8;

pam_mount.conf.5: pam_mount.conf.5.in ${top_builddir}/config.status
	${AM_V_GEN}${replcmd} ${srcdir}/pam_mount.conf.5.in >pam_mount.conf.5;

pam_mount.txt: pam_mount.8
	${AM_V_GEN}man -l pam_mount.8 | perl -pe 's/.\cH//g' >pam_mount.txt;
