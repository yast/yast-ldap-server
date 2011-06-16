# Makefile.am for ldap-server/src

SUBDIRS = YaPI config lib agent tools

yncludedir = @yncludedir@/ldap-server

client_DATA =			\
	ldap-server.ycp		\
	openldap-mirrormode.ycp \
	ldap-server_auto.ycp	\
	ldap-server_proposal.ycp

ynclude_DATA =			\
	helps.ycp		\
	wizards.ycp		\
	widgets.ycp		\
	dialogs.ycp		\
	complex.ycp 		\
	tree_structure.ycp	\
	mirrormode-wizard.ycp

desktop_DATA =			\
	ldap-server.desktop

module_DATA =			\
	LdapServer.pm		\
	LdapDatabase.ycp

EXTRA_DIST = $(client_DATA) $(ynclude_DATA) $(module_DATA) $(desktop_DATA)

include $(top_srcdir)/Makefile.am.common
