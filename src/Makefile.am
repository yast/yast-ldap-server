# Sources for ldap-server

module_DATA = \
  modules/LdapDatabase.rb \
  modules/LdapServer.pm

module1dir = @moduledir@/YaPI
module1_DATA = \
  modules/YaPI/LdapServer.pm

client_DATA = \
  clients/openldap-mirrormode.rb \
  clients/ldap-server.rb \
  clients/ldap-server_proposal.rb \
  clients/ldap-server_auto.rb

yncludedir = @yncludedir@/ldap-server
ynclude_DATA = \
  include/ldap-server/widgets.rb \
  include/ldap-server/wizards.rb \
  include/ldap-server/mirrormode-wizard.rb \
  include/ldap-server/tree_structure.rb \
  include/ldap-server/dialogs.rb \
  include/ldap-server/complex.rb \
  include/ldap-server/helps.rb

scrconf_DATA = \
  scrconf/cfg_openldap.scr \
  scrconf/ldapserver.scr

schemafilesdir = $(schemadir)/autoyast/rnc
schemafiles_DATA = \
  autoyast-rnc/ldap-server.rnc

desktop_DATA = \
  desktop/openldap-mirrormode.desktop \
  desktop/ldap-server.desktop

EXTRA_DIST = $(module_DATA) $(module1_DATA) $(client_DATA) $(ynclude_DATA) $(scrconf_DATA) $(schemafiles_DATA) $(desktop_DATA)

include $(top_srcdir)/Makefile.am.common