#
# spec file for package yast2-ldap-server
#
# Copyright (c) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           yast2-ldap-server
Version:        3.1.1
Release:        0

BuildRoot:      %{_tmppath}/%{name}-%{version}-build
Source0:        %{name}-%{version}.tar.bz2

Group:	System/YaST
License:        GPL-2.0+ and MIT
BuildRequires:	boost-devel gcc-c++ libldapcpp-devel libtool perl-Digest-SHA1 perl-gettext perl-X500-DN pkg-config update-desktop-files yast2 yast2-core-devel yast2-ldap-client yast2-users
BuildRequires:  yast2-devtools >= 3.0.6
BuildRequires:  cyrus-sasl-devel
Requires:	acl net-tools perl perl-Digest-SHA1 perl-gettext perl-X500-DN yast2 yast2-ca-management yast2-ldap-client yast2-perl-bindings

# users/ldap_dialogs.ycp
Requires:       yast2-users >= 2.22.3

# Wizard::SetDesktopTitleAndIcon
Requires:       yast2 >= 2.21.22
Requires:       yast2-ruby-bindings >= 1.0.0

Summary:	YaST2 - OpenLDAP Server Configuration

%description
Provides basic configuration of an OpenLDAP Server over YaST2 Control
Center and during installation.

%prep
%setup -n %{name}-%{version}

%build
%yast_build

%install
%yast_install

rm -f $RPM_BUILD_ROOT/%{yast_plugindir}/libpy2ag_slapdconfig.la
rm -f $RPM_BUILD_ROOT/%{yast_plugindir}/libpy2ag_slapdconfig.so


%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root)
%dir %{yast_yncludedir}/ldap-server
%dir %{yast_moduledir}/YaPI
%{yast_yncludedir}/ldap-server/*
%{yast_clientdir}/ldap-server.rb
%{yast_clientdir}/openldap-mirrormode.rb
%{yast_clientdir}/ldap-server_*.rb
%{yast_moduledir}/LdapServer.*
%{yast_moduledir}/LdapDatabase.*
%{yast_moduledir}/YaPI/LdapServer.pm
%{yast_desktopdir}/ldap-server.desktop
%{yast_desktopdir}/openldap-mirrormode.desktop
%{yast_plugindir}/libpy2ag_slapdconfig.*
%{yast_schemadir}/autoyast/rnc/ldap-server.rnc
%{yast_scrconfdir}/*
%{yast_ybindir}/ldap-server-ssl-check
%doc %{yast_docdir}
%doc COPYING.MIT
