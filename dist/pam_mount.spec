
Name:		pam_mount
Version:	2.5
Release:	0
Group:		System/Libraries
Summary:	A PAM module that can mount volumes for a user session
License:	LGPL
URL:		http://pam-mount.sf.net/

Source:		http://downloads.sf.net/pam-mount/%name-%version.tar.bz2
BuildRequires:	libtool, pam-devel >= 0.99, pkg-config >= 0.19
BuildRequires:	openssl-devel >= 0.9.8, libxml2-devel >= 2.6
BuildRequires:	libHX-devel >= 3.4
BuildRequires:	libcryptsetup-devel >= 1.1.2
%if "%_vendor" == "suse"
BuildRequires:	linux-kernel-headers >= 2.6
Recommends:	cifs-mount
%endif
%if "%_vendor" == "redhat"
BuildRequires:	kernel-headers
%endif
Requires:	device-mapper >= 1.02.48
BuildRoot:	%_tmppath/%name-%version-build
Prefix:		%_prefix

%description
This module is aimed at environments with central file servers that a
user wishes to mount on login and unmount on logout, such as
(semi-)diskless stations where many users can logon.

The module also supports mounting local filesystems of any kind the
normal mount utility supports, with extra code to make sure certain
volumes are set up properly because often they need more than just a
mount call, such as encrypted volumes. This includes SMB/CIFS, FUSE,
dm-crypt and LUKS.

%prep
%setup

%build
%configure --with-slibdir=/%_lib %{?_with_selinux:--with-selinux}
make %{?_smp_mflags};

%install
b="%buildroot";
rm -Rf "$b";
make -i install DESTDIR="$b";
mkdir -p "$b/%_sysconfdir/security" "$b/%_sbindir";

%clean
rm -Rf "%buildroot";

%files
%defattr(-,root,root)
%config(noreplace) %_sysconfdir/security/%name.conf.xml
/%_lib/security/%{name}*.so
%_sbindir/pmvarrun
%_bindir/*
%_sbindir/*
/sbin/*
%_mandir/*/*
%doc doc/*.txt
%if 0%{?_with_selinux:1}
%policy %_sysconfdir/selinux/strict/src/policy/macros/%{name}_macros.te
%policy %_sysconfdir/selinux/strict/src/policy/file_contexts/misc/%name.fc
%endif

%changelog
