# Makefile.am for ldap-server/src

SUBDIRS = YaPI

yncludedir = @yncludedir@/ldap-server

client_DATA =			\
	ldap-server.ycp		\
	ldap-server_auto.ycp	\
	ldap-server_proposal.ycp

ynclude_DATA =			\
	helps.ycp		\
	wizards.ycp		\
	dialogs.ycp		\
	complex.ycp

desktop_DATA =			\
	ldap-server.desktop

module_DATA =			\
	LdapServer.ycp		\
	LdapServer.pm

EXTRA_DIST = $(client_DATA) $(ynclude_DATA) $(module_DATA) $(desktop_DATA)

include $(top_srcdir)/Makefile.am.common
