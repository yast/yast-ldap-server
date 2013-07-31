# encoding: utf-8

# File:        clients/ldap-server_proposal.ycp
# Package:     Configuration of ldap-server
# Summary:     Proposal function dispatcher.
# Authors:     Andreas Bauer <abauer@suse.de>
#
# $Id$
#
# Proposal function dispatcher for ldap-server configuration.
# See source/installation/proposal/proposal-API.txt
module Yast
  class LdapServerProposalClient < Client
    def main
      Yast.import "UI"

      textdomain "ldap-server"

      Yast.import "LdapServer"
      Yast.import "Ldap"
      Yast.import "HTML"
      Yast.import "Label"
      Yast.import "Mode"
      Yast.import "Popup"
      Yast.import "Report"
      Yast.import "Progress"
      Yast.import "Users"
      Yast.import "Package"
      Yast.import "String"
      Yast.import "SuSEFirewall"
      Yast.import "Wizard"

      Yast.include self, "ldap-server/dialogs.rb"

      # The main ()
      Builtins.y2milestone("----------------------------------------")
      Builtins.y2milestone("LdapServer proposal started")
      Builtins.y2milestone("Arguments: %1", WFM.Args)

      @func = Convert.to_string(WFM.Args(0))
      @param = Convert.to_map(WFM.Args(1))
      @ret = {}


      # create a textual proposal
      if @func == "MakeProposal"
        @proposal = ""
        @warning = nil
        @warning_level = nil
        @force_reset = Ops.get_boolean(@param, "force_reset", false)
        @defaults = nil


        if @force_reset || LdapServer.UseDefaults
          if @force_reset && LdapServer.Configured
            # error popup
            Report.Warning(
              _(
                "The LDAP database has already been created. You can change the settings later in the installed system."
              )
            )
          else
            if !Package.Installed("openldap2")
              Builtins.y2milestone(
                "Openldap2 is not installed. --> service disabled"
              )
              LdapServer.WriteServiceEnabled(false)
              # temporarly create the services file for the Firewallsettings
              if Ops.less_or_equal(
                  SCR.Read(
                    path(".target.size"),
                    "/etc/sysconfig/SuSEfirewall2.d/services/openldap"
                  ),
                  0
                )
                SCR.Write(
                  path(".target.string"),
                  "/etc/sysconfig/SuSEfirewall2.d/services/openldap",
                  "TCP=\"ldap ldaps\"\nUDP=\"ldap\"\n"
                )
              end
            else
              LdapServer.WriteServiceEnabled(true)
            end
            @defaults = LdapServer.CreateInitialDefaults
            Ops.set(@defaults, "serviceEnabled", LdapServer.ReadServiceEnabled)
            Ops.set(@defaults, "rootpw_clear", Users.GetRootPassword)
            LdapServer.SetInitialDefaults(@defaults)
            SuSEFirewall.Read
          end
        end

        #y2error( "sysconfig var is '%1'", SCR::Read( .sysconfig.openldap.OPENLDAP_REGISTER_SLP ) );

        if LdapServer.ReadServiceEnabled
          @rootPWString = ""
          @defaults = LdapServer.CreateInitialDefaults
          if !LdapServer.ReadSetupSlave
            if Ops.get_string(@defaults, "rootpw_clear", "") ==
                Users.GetRootPassword
              @rootPWString = _("[root password]")
            else
              @rootPWString = _("[manually set]")
            end
            if Ops.get_string(@defaults, "rootpw_clear", "") == ""
              @warning = _(
                "Unable to retrieve the system root password.  Set an LDAP server password to continue."
              )
              @warning_level = :blocker
            end
            if LdapServer.ReadSetupMaster
              @proposal = _("Setting up LDAP Master Server:")
            else
              @proposal = _("Setting up standalone LDAP Server:")
            end
            @proposal = Ops.add(
              @proposal,
              HTML.List(
                [
                  Ops.add(
                    _("Base DN: "),
                    Ops.get_string(@defaults, "suffix", "")
                  ),
                  Ops.add(
                    _("Root DN: "),
                    Ops.get_string(@defaults, "rootdn", "")
                  ),
                  Ops.add(_("LDAP Password: "), @rootPWString)
                ]
              )
            )
          else
            @syncrepl = LdapServer.ReadSyncreplBaseConfig
            @proposal = Ops.add(
              _("Setting up LDAP Slave Server"),
              HTML.List(
                [
                  Ops.add(
                    Ops.add(
                      Ops.add(
                        Ops.add(
                          Ops.add(
                            _("Provider: "),
                            Ops.get_string(
                              @syncrepl,
                              ["provider", "protocol"],
                              ""
                            )
                          ),
                          "://"
                        ),
                        Ops.get_string(@syncrepl, ["provider", "target"], "")
                      ),
                      ":"
                    ),
                    Builtins.tostring(
                      Ops.get_integer(@syncrepl, ["provider", "port"], 0)
                    )
                  )
                ]
              )
            )
          end
          # Try to get Firewall status
          @fw_text = ""
          if SuSEFirewall.GetEnableService
            @known_interfaces = SuSEFirewall.GetListOfKnownInterfaces
            @is_ldap_enabled = false
            if Ops.greater_than(Builtins.size(@known_interfaces), 0)
              Builtins.y2milestone("Interfaces: %1", @known_interfaces)
              # all known interfaces for testing
              @used_zones = SuSEFirewall.GetZonesOfInterfaces(@known_interfaces)
              Builtins.y2milestone("Zones used by firewall: %1", @used_zones)

              Builtins.foreach(@used_zones) do |zone|
                if SuSEFirewall.IsServiceSupportedInZone(
                    "service:openldap",
                    zone
                  )
                  @is_ldap_enabled = true
                end
              end
            end
            textdomain "base"
            @fw_text = _("Open Port in Firewall") + ": "
            textdomain "ldap-server"
            if @is_ldap_enabled
              @fw_text = Ops.add(@fw_text, HTML.Bold(_("YES")))
            else
              @fw_text = Ops.add(@fw_text, HTML.Bold(_("NO")))
            end
          else
            textdomain "base"
            @fw_text = _("Firewall is disabled")
            textdomain "ldap-server"
          end
          @proposal = Ops.add(
            Ops.add(
              Ops.add(
                Ops.add(@proposal, _("Register at SLP Daemon: ")),
                HTML.Bold(
                  Ops.get_boolean(@defaults, "slpRegister", false) ?
                    _("YES") :
                    _("NO")
                )
              ),
              HTML.Newline
            ),
            @fw_text
          )
        else
          @proposal = Ops.add(_("Start LDAP Server: "), HTML.Bold(_("NO")))
        end


        @ret = {
          "preformatted_proposal" => @proposal,
          "warning_level"         => @warning_level,
          "warning"               => @warning
        }
      # run the module
      elsif @func == "AskUser"
        @stored = nil
        @seq = nil
        if LdapServer.Configured
          # error popup
          Report.Warning(
            _(
              "The LDAP database has already been created. You can change the settings later in the installed system."
            )
          )
          @seq = :back
        else
          #        stored = LdapServer::Export();
          @seq = Convert.to_symbol(
            WFM.CallFunction("ldap-server", [path(".propose")])
          )
          if @seq == :next
            LdapServer.WriteServiceEnabled(true)
          elsif @seq == :disable
            LdapServer.WriteServiceEnabled(false)
            @seq = :next
          end 
          #        if(seq != `next) LdapServer::Import(stored);
        end
        Builtins.y2debug("stored=%1", @stored)
        Builtins.y2debug("seq=%1", @seq)
        @ret = { "workflow_sequence" => @seq }
      # create titles
      elsif @func == "Description"
        @ret = {
          # Rich text title for LdapServer in proposals
          "rich_text_title" => _(
            "OpenLDAP Server"
          ),
          # Menu title for LdapServer in proposals
          "menu_title"      => _(
            "Open&LDAP Server"
          ),
          "id"              => "ldap-server"
        }
      # write the proposal
      elsif @func == "Write"
        return deep_copy(@ret) if LdapServer.Configured

        if !Package.Installed("openldap2")
          #remove temp file
          SCR.Execute(
            path(".target.remove"),
            "/etc/sysconfig/SuSEfirewall2.d/services/openldap"
          )
        end
        if LdapServer.ReadServiceEnabled
          # ensure openldap2 package is installed
          if !Package.Install("openldap2")
            if !Package.Available("openldap2")
              # translators: error popup before aborting the module
              Popup.Error(
                Builtins.sformat(
                  _(
                    "The package '%1' is not available.\n" +
                      "YaST2 cannot continue the configuration\n" +
                      "without installing the package."
                  ),
                  "openldap2"
                )
              )
            else
              # translators: error popup before aborting the module
              Popup.Error(
                _(
                  "YaST2 cannot continue the configuration\nwithout installing the required packages."
                )
              )
            end

            return deep_copy(@ret)
          end

          if LdapServer.ReadSetupSlave
            Wizard.CreateDialog
            Wizard.SetDesktopTitleAndIcon("ldap-server")
            @slave_ret = Convert.to_symbol(SlaveSetupDialog())
            Wizard.CloseDialog
            if @slave_ret == :next
              LdapServer.SetupRemoteForReplication
            else
              Report.Error(
                _(
                  "OpenLDAP Replication Setup failed. Reconfigure after the installation has finished."
                )
              )
              return deep_copy(@ret)
            end
          end
          LdapServer.ReadFromDefaults
          @defaults = LdapServer.CreateInitialDefaults
          Progress.set(false)
          Ldap.Read
          Progress.set(true)
          @ldapclient_defaults = Ldap.Export
          Ops.set(@ldapclient_defaults, "ldap_server", "localhost")
          Ops.set(
            @ldapclient_defaults,
            "base_config_dn",
            Ops.add("ou=ldapconfig,", Ops.get_string(@defaults, "suffix", ""))
          )
          Ops.set(
            @ldapclient_defaults,
            "bind_dn",
            Ops.get_string(@defaults, "rootdn", "")
          )
          Ops.set(
            @ldapclient_defaults,
            "ldap_domain",
            Ops.get_string(@defaults, "suffix", "")
          )
          Ops.set(@ldapclient_defaults, "ldap_tls", false)
          Ops.set(@ldapclient_defaults, "file_server", true)
          Ops.set(@ldapclient_defaults, "create_ldap", true)

          if !LdapServer.HaveCommonServerCertificate
            Report.Error(
              _(
                "OpenLDAP Server: Common server certificate not available.\nStartTLS is disabled."
              )
            )
          else
            Ops.set(@ldapclient_defaults, "ldap_tls", true)
            LdapServer.WriteTlsConfigCommonCert
          end

          Ldap.SetDefaults(@ldapclient_defaults)
          Ldap.SetBindPassword(Ops.get_string(@defaults, "rootpw_clear", ""))
          LdapServer.WriteSLPEnabled(
            Ops.get_boolean(@defaults, "slpRegister", false)
          )
          LdapServer.Write
        end
      else
        Builtins.y2error("unknown function: %1", @func)
      end

      # Finish
      Builtins.y2debug("ret=%1", @ret)
      Builtins.y2milestone("LdapServer proposal finished")
      Builtins.y2milestone("----------------------------------------")
      deep_copy(@ret) 

      # EOF
    end
  end
end

Yast::LdapServerProposalClient.new.main
