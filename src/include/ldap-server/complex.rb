# encoding: utf-8

# File:	include/ldap-server/complex.ycp
# Package:	Configuration of ldap-server
# Summary:	Dialogs definitions
# Authors:	Andreas Bauer <abauer@suse.de>
#
# $Id$
module Yast
  module LdapServerComplexInclude
    def initialize_ldap_server_complex(include_target)
      Yast.import "UI"

      textdomain "ldap-server"

      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "Wizard"
      Yast.import "LdapServer"
      Yast.import "Package"
      Yast.import "Service"

      Yast.include include_target, "ldap-server/helps.rb"
    end

    def DisplayError(error)
      error = deep_copy(error)
      if Ops.get(error, "msg") != nil
        if Ops.get(error, "details") != nil
          Popup.ErrorDetails(
            Ops.get(error, "msg", ""),
            Ops.get(error, "details", "")
          )
        else
          Popup.Error(Ops.get(error, "msg", ""))
        end
      end

      nil
    end

    # Read settings dialog
    # @return `abort if aborted and `next otherwise
    def ReadDialog
      Wizard.RestoreHelp(Ops.get_string(@HELPS, "read", ""))

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
        return :abort
      end

      ret = LdapServer.Read
      if !ret
        DisplayError(LdapServer.ReadError)
        return :abort
      end
      hasBackconfig = LdapServer.IsUsingBackconfig
      configModified = LdapServer.SlapdConfChanged #original shipped slapd.conf?

      serviceEnabled = LdapServer.ReadServiceEnabled
      serviceRunning = LdapServer.ReadServiceRunning
      switchToBackConfig = false
      convert = false

      #y2milestone("OpenLDAP running: %1", isRunning);
      Builtins.y2milestone("OpenLDAP using backConfig: %1", hasBackconfig)
      Builtins.y2milestone("OpenLDAP modifed config: %1", configModified)
      configFile = "/etc/openldap/slapd.conf"
      if !hasBackconfig
        if configModified
          return :migrate
        else
          # Start new config wizward
          LdapServer.InitDbDefaults
          return :initial
        end
      else
        if !configModified
          # Start new config wizward
          LdapServer.InitDbDefaults
          return :initial
        elsif !serviceRunning
          ret2 = Popup.AnyQuestion3(
            _("Existing configuration detected."),
            _(
              "You have an existing configuration, but the LDAP server is currently not running.\n" +
                "Do you want to start the server now and re-read its configuration data or do you \n" +
                "want to create a new configuration from scratch?"
            ),
            _("Restart"),
            Label.CancelButton,
            _("New Configuration"),
            :focus_yes
          )
          if ret2 == :yes
            LdapServer.WriteRestartRequired(true)
            return :reread
          elsif ret2 == :no
            return :abort
          elsif ret2 == :retry
            # Start new config wizward
            LdapServer.InitDbDefaults
            return :initial
          end
        end
      end

      :next
    end

    def MigrationMainDialog
      caption = "Migrate existing Configuration"
      summary = _(
        "Your system is currently configured to use the configuration file\n" +
          "/etc/openldap/slapd.conf. YaST only supports the dynamic configuration\n" +
          "database of OpenLDAP (back-config). Do you want to migrate your existing\n" +
          "configuration to the configuration database?\n"
      )
      contents = VBox(
        HSquash(
          RadioButtonGroup(
            Id(:rb),
            VBox(
              Label(summary),
              Left(
                RadioButton(Id(0), _("Migrate existing configuration"), true)
              ),
              Left(
                RadioButton(Id(1), _("Create a new configuration from scratch"))
              )
            )
          )
        )
      )

      Wizard.SetContentsButtons(
        caption,
        contents,
        Ops.get_string(@HELPS, "summary", ""),
        Label.BackButton,
        Label.NextButton
      )
      ret = :next
      while true
        ret = Convert.to_symbol(UI.UserInput)

        # abort?
        if ret == :abort || ret == :cancel
          if Popup.ReallyAbort(true)
            break
          else
            next
          end
        elsif ret == :next
          current = Convert.to_integer(UI.QueryWidget(Id(:rb), :CurrentButton))
          if current == 0
            ret = :next
          else
            ret = :initial
          end
          break
        elsif ret == :back
          break
        else
          Builtins.y2error("unexpected retcode: %1", ret)
          next
        end
      end

      ret
    end

    def DoMigration
      LdapServer.UseLdapiForConfig(true)
      if !LdapServer.MigrateSlapdConf
        Builtins.y2milestone("LdapServer::MigrateSlapdConf failed")
        DisplayError(LdapServer.ReadError)
        return :abort
      end
      LdapServer.Read
      :next
    end

    # Write service settings dialog. This dialog writes only the service
    # settings (sysconfig and init.d stuff)
    # @return `reread if configuration needs to be reread and `next otherwise
    def WriteServiceDialog
      Wizard.RestoreHelp(Ops.get_string(@HELPS, "write", ""))
      ret = LdapServer.WriteServiceSettings
      ret ? :next : :reread
    end

    # Write settings dialog
    # @return `abort if aborted and `next otherwise
    def WriteDialog
      Wizard.RestoreHelp(Ops.get_string(@HELPS, "write", ""))
      ret = LdapServer.Write
      if !ret
        DisplayError(LdapServer.ReadError)
        return :abort
      end
      #    ret = LdapServer::WritePPolicyObjects();
      ret ? :next : :abort
    end

    # Summary dialog
    # @return dialog result
    def SummaryDialog
      # LdapServer summary dialog caption
      caption = _("LDAP Server Configuration Summary")

      summary = LdapServer.Summary

      # Frame label
      contents = VBox(
        RichText(summary) #,
        #`Right(
        #    `PushButton( `id(`pb_advanced), _("Advanced Configuration") )
        #)
      )

      Wizard.SetContentsButtons(
        caption,
        contents,
        Ops.get_string(@HELPS, "summary", ""),
        Label.BackButton,
        Label.FinishButton
      )

      ret = nil
      while true
        ret = UI.UserInput

        # abort?
        if ret == :abort || ret == :cancel
          if Popup.ReallyAbort(true)
            break
          else
            next
          end
        elsif ret == :pb_advanced
          Popup.Error("Not there yet")
          LdapServer.ReadFromDefaults
          ret = :advanced
          break
        elsif ret == :next
          if !LdapServer.ReadFromDefaults
            DisplayError(LdapServer.ReadError)
            ret = :abort
          end
          break
        elsif ret == :back
          break
        else
          Builtins.y2error("unexpected retcode: %1", ret)
          next
        end
      end

      deep_copy(ret)
    end
  end
end
