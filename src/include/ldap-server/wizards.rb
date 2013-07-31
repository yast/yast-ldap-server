# encoding: utf-8

# File:	include/ldap-server/wizards.ycp
# Package:	Configuration of ldap-server
# Summary:	Wizards definitions
# Authors:	Andreas Bauer <abauer@suse.de>
#              Ralf Haferkamp <rhafer@suse.de>
#
# $Id$
module Yast
  module LdapServerWizardsInclude
    def initialize_ldap_server_wizards(include_target)
      Yast.import "UI"

      textdomain "ldap-server"

      Yast.import "Sequencer"
      Yast.import "Wizard"

      Yast.include include_target, "ldap-server/complex.rb"
      Yast.include include_target, "ldap-server/dialogs.rb"
    end

    # Main workflow of the ldap-server configuration
    # @return sequence result
    def MainSequence
      # FIXME: adapt to your needs
      aliases = { "tree" => lambda { TreeDialog() }, "writeservice" => lambda do
        WriteServiceDialog()
      end }

      sequence = {
        "ws_start"     => "tree",
        "tree"         => {
          :abort  => :abort,
          :back   => :abort,
          :cancel => :abort,
          :next   => :next,
          :reread => "writeservice",
          :empty  => :empty
        },
        "writeservice" => { :reread => :reread }
      }

      Wizard.SetDesktopTitleAndIcon("ldap-server")
      ret = Sequencer.Run(aliases, sequence)
      UI.CloseDialog
      deep_copy(ret)
    end

    def InstProposalSequence
      caption = _("LDAP Server Configuration")
      contents = Label(_("Initializing..."))

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ldap-server")
      Wizard.SetContentsButtons(
        caption,
        contents,
        "",
        Label.BackButton,
        Label.NextButton
      )
      Wizard.SetAbortButton(:abort, Label.CancelButton)

      LdapServer.WriteModeInstProposal(true)
      aliases = {
        "startup"     => lambda { EnableServiceDialog() },
        "servertype"  => lambda { ServerTypeDialog() },
        "database"    => lambda { ProposalDialog() },
        "mastersetup" => lambda { MasterSetupDialog() },
        "slavesetup"  => lambda { SlaveSetupDialog() }
      }

      sequence = {
        "ws_start"    => "startup",
        "startup"     => {
          :next   => "servertype",
          :abort  => :abort,
          :finish => :disable
        },
        "servertype"  => {
          :next        => "database",
          :slave_setup => "slavesetup",
          :abort       => :abort
        },
        "slavesetup"  => { :next => :next, :abort => :abort },
        "database"    => {
          :mastersetup => "mastersetup",
          :next        => :next,
          :abort       => :abort
        },
        "mastersetup" => { :next => :next, :abort => :abort }
      }

      Builtins.y2milestone("--> starting InstProposalSequence")

      ret = Sequencer.Run(aliases, sequence)

      Builtins.y2milestone("<-- InstProposalSequence finished ")

      UI.CloseDialog
      LdapServer.WriteModeInstProposal(false)

      deep_copy(ret)
    end

    def ProposalSequence
      # Initialization dialog caption
      caption = _("LDAP Server Configuration")
      # Initialization dialog contents
      contents = Label(_("Initializing..."))

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ldap-server")
      Wizard.SetContentsButtons(
        caption,
        contents,
        "",
        Label.BackButton,
        Label.NextButton
      )

      aliases = {
        "startup"            => lambda { EnableServiceDialog() },
        "servertype"         => lambda { ServerTypeDialog() },
        "tlssettings"        => lambda { TlsConfigDialog() },
        "database"           => lambda { ProposalDialog() },
        "summary"            => lambda { SummaryDialog() },
        "advanced"           => lambda { MainSequence() },
        "write"              => lambda { WriteDialog() },
        "slavesetup"         => lambda { SlaveSetupDialog() },
        "mastersetup"        => lambda { MasterSetupDialog() },
        "replicationsummary" => lambda { ReplicatonSetupSummaryDialog() }
      }

      sequence = {
        "ws_start"           => "startup",
        "startup"            => {
          :next   => "servertype",
          :abort  => :abort,
          :finish => :abort
        },
        "servertype"         => {
          :next        => "tlssettings",
          :slave_setup => "slavesetup"
        },
        "slavesetup"         => { :next => "replicationsummary" },
        "replicationsummary" => { :next => "write" },
        "tlssettings"        => { :next => "database" },
        "database"           => {
          :next        => "summary",
          :mastersetup => "mastersetup",
          :abort       => :abort
        },
        "mastersetup"        => { :next => "summary", :abort => :abort },
        "summary"            => {
          :next     => "write",
          :abort    => :abort,
          :advanced => "advanced"
        },
        "advanced"           => { :abort => :abort, :next => "write" },
        "write"              => { :abort => :abort, :next => :next }
      }

      Builtins.y2milestone("--> starting ProposalSequence")

      ret = Sequencer.Run(aliases, sequence)

      Builtins.y2milestone("<-- ProposalSequence finished ")

      UI.CloseDialog

      deep_copy(ret)
    end

    def MigrateSequence
      # Initialization dialog caption
      caption = _("LDAP Server Configuration")
      # Initialization dialog contents
      contents = Label(_("Initializing..."))


      aliases = {
        "startup"  => lambda { MigrationMainDialog() },
        "proposal" => lambda { ProposalSequence() },
        #        "authconfig"    : ``( MigrationDialog() ),
        "migrate"  => lambda do
          DoMigration()
        end
      }

      sequence = {
        "ws_start" => "startup",
        "startup"  => {
          :abort   => :abort,
          :next    => "migrate",
          :initial => "proposal"
        },
        #        "authconfig"   : $[
        #            `next   : "migrate"
        #        ],
        "migrate"  => {
          :next => :next
        },
        "proposal" => { :next => :next }
      }

      Builtins.y2milestone("--> starting MigrateSequence")

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ldap-server")
      ret = Sequencer.Run(aliases, sequence)

      Builtins.y2milestone("--> MigrateSequence finished ")

      UI.CloseDialog

      deep_copy(ret)
    end

    # Whole configuration of ldap-server
    # @return sequence result
    def LdapServerSequence
      aliases = {
        "read"         => lambda { ReadDialog() },
        "migrate"      => lambda { MigrateSequence() },
        "propose"      => lambda { ProposalSequence() },
        "main"         => lambda { MainSequence() },
        "writeservice" => lambda { WriteServiceDialog() },
        "write"        => lambda { WriteDialog() }
      }

      sequence = {
        "ws_start"     => "read",
        "read"         => {
          :abort   => :abort,
          :initial => "propose",
          :migrate => "migrate",
          :next    => "main",
          :reread  => "writeservice"
        },
        "migrate"      => {
          :abort   => :abort,
          :initial => "propose",
          :next    => "main"
        },
        "propose"      => { :next => :next, :abort => :abort },
        "main"         => {
          :abort  => :abort,
          :next   => "write",
          :reread => "read"
        },
        "writeservice" => { :reread => "read" },
        "write"        => { :abort => :abort, :next => :next }
      }

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ldap-server")

      ret = Sequencer.Run(aliases, sequence)

      UI.CloseDialog
      deep_copy(ret)
    end

    # Whole configuration of ldap-server but without reading and writing.
    # For use with autoinstallation.
    # @return sequence result
    def LdapServerAutoSequence
      # Initialization dialog caption
      caption = _("LDAP Server Configuration")
      # Initialization dialog contents
      contents = Label(_("Initializing..."))

      Builtins.y2milestone("--> starting LdapServerAutoSequence")

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ldap-server")
      Wizard.SetContentsButtons(
        caption,
        contents,
        "",
        Label.BackButton,
        Label.NextButton
      )

      ret = InstProposalSequence()

      UI.CloseDialog

      Builtins.y2milestone("--> LdapServerAutoSequence finished ")

      deep_copy(ret)
    end
  end
end
