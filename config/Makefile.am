# -*- Makefile -*-

securitydir   = ${sysconfdir}/security
dist_security_DATA = pam_mount.conf.xml

if SELINUX
selinux_fcdir   = ${sysconfdir}/selinux/strict/src/policy/file_contexts/misc
selinux_tedir   = ${sysconfdir}/selinux/strict/src/policy/macros
dist_selinux_fc_DATA = pam_mount.fc
dist_selinux_te_DATA = pam_mount_macros.te
endif

dtddir = ${datadir}/xml/pam_mount/dtd
if WITH_DTD
dist_dtd_DATA = pam_mount.conf.xml.dtd
endif

.PHONY: validate-config
validate-config:
	xmllint --nonet --noout --loaddtd --valid pam_mount.conf.xml
