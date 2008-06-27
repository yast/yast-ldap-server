#! /usr/bin/perl -w
# File:		modules/LdapServer.pm
# Package:	Configuration of ldap-server
# Summary:	LdapServer settings, input and output functions
# Authors:	Ralf Haferkamp <rhafer@suse.de>, Andreas Bauer <abauer@suse.de>
#
# $Id$
#
# Representation of the configuration of ldap-server.
# Input and output routines.


package LdapServer;

use strict;

use Data::Dumper;

use X500::DN;
use ycp;
use YaST::YCP qw(Boolean);

our %TYPEINFO;

YaST::YCP::Import ("Progress");
YaST::YCP::Import ("Service");

my %error = ( msg => undef, details => undef );

my $usesBackConfig = 0;
my $slapdConfChanged = 0;
my $serviceEnabled = 0;
my $registerSlp = 0;
my %dbDefaults = ();

my @databases = ();
my @schema = ();

##
 # Read all ldap-server settings
 # @return true on success
 #
BEGIN { $TYPEINFO{Read} = ["function", "boolean"]; }
sub Read {
    y2milestone("");

    my $progressItems = [ "Reading Startup Configuration", 
            "Reading Configuration Backend", 
            "Reading Configuration Data" ];
    Progress->New("Initializing LDAP Server Configuration", "Blub", 3, $progressItems, $progressItems, "");
    Progress->NextStage();
    my $serviceInfo = Service->FullInfo("ldap");
    my $isRunning = ( defined $serviceInfo->{"started"}) && ($serviceInfo->{"started"} == 0); # 0 == "running"
    my $isEnabled = $serviceInfo->{"start"} && $serviceInfo->{"start"} > 0;

    y2milestone("Serviceinfo: ". Data::Dumper->Dump([$serviceInfo]));
    y2milestone("IsRunning: " . $isRunning . " IsEnabled " . $isEnabled);
    
    Progress->NextStage();
    my $configBackend = SCR->Read('.sysconfig.openldap.OPENLDAP_CONFIG_BACKEND');
    y2milestone("ConfigBackend: " . $configBackend);

    Progress->NextStage();
    if ( $configBackend eq "ldap" )
    {
        $usesBackConfig = 1;
        if ( $isRunning )
        {
            # assume a changed config as we don't ship a default for back-config
            $slapdConfChanged = 1;
            # How do we get the LDAP password?
            y2milestone("LDAP server is running. How should I connect?");
            SCR->Execute('.ldapserver.init' );
            my $rc = SCR->Read('.ldapserver.databases');
            y2milestone("Databases: ". Data::Dumper->Dump([$rc]));
            @databases = @{$rc};
        }
        else
        {
            # LDAP Server not running. Use slapcat to import the config
            y2milestone("Using slapcat to import configuration");
            my $rc = SCR->Execute('.target.bash_output', 
                    "/usr/sbin/slapcat -F /etc/openldap/slapd.d -b cn=config" );
#            y2milestone("slapcat result: ". Data::Dumper->Dump([$rc]));
            SCR->Execute('.ldapserver.initFromLdif', $rc->{'stdout'});
            $rc = SCR->Read('.ldapserver.databases' );
            y2milestone("Databases: ". Data::Dumper->Dump([$rc]));
            #$rc = SCR->Read('.ldapserver.global.tlsSettings' );
            #y2milestone("tlsSettings: ". Data::Dumper->Dump([$rc]));
        }
    }
    else
    {
        # Check if the config file was changed, otherwise we can assume 
        # that this server is unconfigured and start from scratch
        my $exitcode = SCR->Execute('.target.bash',
                "rpm -Vf /etc/openldap/slapd.conf | ".
                "grep \"/etc/openldap/slapd.conf\"| ".
                "cut -d \" \" -f 1 | grep 5" );

        if ( $exitcode == 0 )
        {
            $slapdConfChanged = 1;
        }

        y2milestone("ConfigModifed: " . $slapdConfChanged);
    }
        
    Progress->Finish();
    return 1;
}

##
 # Write all ldap-server settings
 # @return true on success
 #
BEGIN { $TYPEINFO{Write} = ["function", "boolean"]; }
sub Write {
    my $self = shift;
    y2milestone("LdapServer::Write");
    my $ret = 1;
    if ( ! $usesBackConfig ) 
    {
        my $progressItems = [ _("Writing Startup Configuration"),
                _("Cleaning up config directory"),
                _("Creating Configuration"),
                _("Starting OpenLDAP Server")];
        Progress->New("Writing OpenLDAP Server Configuration", "", 4, $progressItems, $progressItems, "");

        Progress->NextStage();

        my $rc = SCR->Write('.sysconfig.openldap.OPENLDAP_CONFIG_BACKEND', 'ldap');
        if ( ! $rc )
        {
            y2error("Error while switch to config backend");
            $self->SetError( _("Switch from slapd.conf to config backend failed.") );
            Progress->Finish();
            return 0;
        }
        $rc = SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPI', 'yes');
        if ( ! $rc )
        {
            y2error("Error while enabling LDAPI listener");
            $self->SetError( _("Enabling thi LDAPI Protocol listener failed.") );
            Progress->Finish();
            return 0;
        }
        $rc = SCR->Read('.sysconfig.openldap.OPENLDAP_START_LDAPI');
        y2milestone(Data::Dumper->Dump([$rc]));

        # FIXME:
        # Explicit cache flush, see bnc#350581 for details
        SCR->Write(".sysconfig.openldap", undef);
        Progress->NextStage();

        $rc = SCR->Execute('.target.bash', 'rm -rf /etc/openldap/slapd.d/cn=config*' );
        if ( $rc )
        {
            y2error("Error while cleaning up to config directory");
            $self->SetError( _("Config Directory cleanup failed.") );
            Progress->Finish();
            return 0;
        }

        Progress->NextStage();
        $rc = SCR->Execute('.target.bash_output', 'mktemp /tmp/slapd-conf-ldif.XXXXXX' );
        if ( $rc->{'exit'} == 0 )
        {
            my $tmpfile = $rc->{'stdout'};
            chomp $tmpfile;
            y2milestone("using tempfile: ".$tmpfile );
            my $ldif = SCR->Read('.ldapserver.configAsLdif' );
            y2milestone($ldif);
            $rc = SCR->Write('.target.string', $tmpfile, $ldif );
            if ( $rc )
            {
                $rc = SCR->Execute('.target.bash_output', 
                        "/usr/sbin/slapadd -F /etc/openldap/slapd.d -b cn=config -l $tmpfile" );
                if ( $rc->{'exit'} )
                {
                    y2error("Error during slapadd:" .$rc->{'stderr'});
                    $ret = 0;
                }
            }
            else
            {
                y2error("Error while write configuration to LDIF file");
                $ret = 0;
            }
            # cleanup
            SCR->Execute('.target.bash', "rm -f $tmpfile" );
        }
        Progress->NextStage();

        $rc = Service->Enable("ldap");
        if ( ! $rc )
        {
            y2error("Error while enabing the LDAP Service: ". Service->Error() );
            $self->SetError( _("Enabling the LDAP Service failed.") );
            Progress->Finish();
            return 0;
        }
        $rc = Service->Restart("ldap");
        if (! $rc )
        {
            y2error("Error while starting the LDAP service");
            $self->SetError( _("Starting the LDAP service failed.") );
            Progress->Finish();
            return 0;
        }

        Progress->Finish();
    } else {
        SCR->Execute('.ldapserver.commitChanges' );
    }
    sleep(1);
    return $ret;
}

##
 # Get all ldap-server settings from the first parameter
 # (For use by autoinstallation.)
 # @param settings The YCP structure to be imported.
 # @return boolean True on success
 #
BEGIN { $TYPEINFO{Import} = ["function", "boolean", [ "map", "any", "any" ] ]; }
sub Import {
    my $self = shift;
    my $hash = shift;

    return 1;
}

##
 # Dump the ldap-server settings to a single map
 # (For use by autoinstallation.)
 # @return map Dumped settings (later acceptable by Import ())
 #
BEGIN { $TYPEINFO{Export}  =["function", [ "map", "any", "any" ] ]; }
sub Export {
    my $self = shift;

    my $hash = {};

    return $hash;
}

##
 # Create a textual summary and a list of unconfigured cards
 # @return summary of the current configuration
 #
BEGIN { $TYPEINFO{Summary} = ["function", "string" ]; }
sub Summary {
    # Configuration summary text for autoyast
    my $self = shift;
    my $defaults = $self->GetInitialDefaults();
    my $string;

    $string .= '<h2>'._("Startup Configuration").'</h2>'
            .'<p>'._("Start LDAP Server: ").'<code>'.($defaults->{'serviceEnabled'}->value?_("Yes"):_("No")).'</code></p>'
            .'<p>'._("Register at SLP Service: ").'<code>'.($defaults->{'slpRegister'}->value?_("Yes"):_("No")).'</code></p>'
            .'<h2>'._("Create initial Database with the following Parameters").'</h2>'
            .'<p>'._("Database Suffix: ").'<code>'.$defaults->{'basedn'}.'</code></p>'
            .'<p>'._("Administrator DN: ").'<code>'.$defaults->{'rootdn'}.'</code></p>';

    return $string;
}

##
 # Create an overview table with all configured cards
 # @return table items
 #
BEGIN { $TYPEINFO{Overview} = ["function", [ "list", "string" ] ]; }
sub Overview {
    # TODO FIXME: your code here...
    return ();
}

##
 # Return packages needed to be installed and removed during
 # Autoinstallation to insure module has all needed software
 # installed.
 # @return map with 2 lists.
 #
BEGIN { $TYPEINFO{AutoPackages} = ["function", ["map", "string", ["list", "string"]]]; }
sub AutoPackages {
    # TODO FIXME: your code here...
    my %ret = (
	"install" => (),
	"remove" => (),
    );
    return \%ret;
}

##
 # Data was modified?
 # @return true if modified
 #
BEGIN { $TYPEINFO {Modified} = ["function", "boolean"]; }
sub Modified {
    y2milestone();
    return 0;
}
BEGIN { $TYPEINFO {ReadServiceEnabled} = ["function", "boolean"]; }
sub ReadServiceEnabled {
    y2milestone("ReadServiceEnabled $serviceEnabled");
    return $serviceEnabled;
}

BEGIN { $TYPEINFO {SetServiceEnabled} = ["function", "boolean", "boolean"]; }
sub SetServiceEnabled {
    my $self = shift;
    $serviceEnabled = shift;
    return 1;
}

BEGIN { $TYPEINFO {ReadSLPEnabled} = ["function", "boolean"]; }
sub ReadSLPEnabled {
    y2milestone("ReadSLPEnabled");
    return $registerSlp;
}

BEGIN { $TYPEINFO {SetSlpEnabled} = ["function", "boolean", "boolean"]; }
sub SetSlpEnabled {
    my $self = shift;
    y2milestone("ReadServiceEnabled");
    $registerSlp = shift;
    return 1;
}

BEGIN { $TYPEINFO {IsUsingBackconfig} = ["function", "boolean"]; }
sub IsUsingBackconfig 
{
    return $usesBackConfig;
}

BEGIN { $TYPEINFO {SlapdConfChanged} = ["function", "boolean"]; }
sub SlapdConfChanged
{
    return $slapdConfChanged;
}

sub SetError
{
    my $self = shift;
    my ( $msg, $details ) = @_;
    $error{'msg'} = $msg;
    $error{'details'} = $details;
}

BEGIN { $TYPEINFO {GetError} = ["function", ["map", "string", "string"] ]; }
sub GetError
{
    return \%error;
}

BEGIN { $TYPEINFO {GetLogLevels} = ["function", [ "list", "string" ] ]; }
sub GetLogLevels
{
    return  SCR->Read('.ldapserver.global.loglevel' );
}

BEGIN { $TYPEINFO {SetLogLevels} = ["function", "boolean", [ "list", "string" ] ]; }
sub SetLogLevels
{
    my $self = shift;
    my $lvls = shift;
    SCR->Write('.ldapserver.global.loglevel', $lvls );
    return 1;
}

BEGIN { $TYPEINFO {GetAllowFeatures} = ["function", [ "list", "string" ] ]; }
sub GetAllowFeatures
{
    return  SCR->Read('.ldapserver.global.allow' );
}

BEGIN { $TYPEINFO {GetDisallowFeatures} = ["function", [ "list", "string" ] ]; }
sub GetDisallowFeatures
{
    return  SCR->Read('.ldapserver.global.disallow' );
}

BEGIN { $TYPEINFO {SetAllowFeatures} = ["function", "boolean", [ "list", "string" ] ]; }
sub SetAllowFeatures
{
    my $self = shift;
    my $features = shift;
    SCR->Write('.ldapserver.global.allow', $features );
    return 1;
}

BEGIN { $TYPEINFO {SetDisallowFeatures} = ["function", "boolean", [ "list", "string" ] ]; }
sub SetDisallowFeatures
{
    my $self = shift;
    my $features = shift;
    SCR->Write('.ldapserver.global.disallow', $features );
    return 1;
}

BEGIN { $TYPEINFO {MigrateSlapdConf} = ["function", "boolean"]; }
sub MigrateSlapdConf
{
    my $self = shift;
    my $progressItems = [ _("Cleaning up directory for config database"),
            _("Converting slapd.conf to config database"), 
            _("Switching startup configuration to use config database")]; 
    Progress->New("Migrating LDAP Server Configuration", "Blub", 3, $progressItems, $progressItems, "");
    Progress->NextStage();
    Progress->NextStage();

    my $rc = SCR->Execute('.target.bash_output', 
                    "/usr/sbin/slaptest -f /etc/openldap/slapd.conf -F /etc/openldap/slapd.d" );
    if ( $rc->{'exit'} ) 
    {
        y2error("Error while migration slapd.conf");
        my $details = _("Output of \"slaptest\":\n"). $rc->{'stderr'};
        $self->SetError( _("Migration of existing configuration failed."), $details );
        Progress->Finish();
        return 0;
    }
    Progress->NextStage();
    $rc = SCR->Write('.sysconfig.openldap.OPENLDAP_CONFIG_BACKEND', 'ldap');
    if ( ! $rc )
    {
        y2error("Error while switch to config backend");
        $self->SetError( _("Switch from slapd.conf to config backend failed.") );
        Progress->Finish();
        return 0;
    }
    Progress->Finish();
    return 1;
}

BEGIN { $TYPEINFO {GetInitialDefaults} = ["function", [ "map", "string", "any"] ]; }
sub GetInitialDefaults
{
    y2milestone("GetInitialDefaults");
    my $self = shift;
    if ( ! keys(%dbDefaults ) ) {
        $self->InitDbDefaults();
    }
    y2milestone(Data::Dumper->Dump([\%dbDefaults]));
    return \%dbDefaults;
}

BEGIN { $TYPEINFO {SetInitialDefaults} = ["function", "boolean", [ "map", "string", "any" ] ]; }
sub SetInitialDefaults
{
    my $self = shift;
    my $defaults = shift;
    $defaults->{'serviceEnabled'} =  YaST::YCP::Boolean($defaults->{'serviceEnabled'});
    $defaults->{'slpRegister'} =  YaST::YCP::Boolean($defaults->{'slpRegister'});
    y2milestone("SetInitialDefaults: ". Data::Dumper->Dump([$defaults]));
    %dbDefaults = %$defaults;
    return 1;
}

BEGIN { $TYPEINFO {InitDbDefaults} = ["function", "boolean"]; }
sub InitDbDefaults
{
    y2milestone("InitDbDefaults");
    my $self = shift;
    # generate base dn from domain;
    my $rc = SCR->Execute( '.target.bash_output', "/bin/hostname -d" );
    my $domain = $rc->{"stdout"};
    if ( $domain eq "" )
    {
        $domain = "site";
    }
    chomp($domain);
    y2milestone( "domain is: <".$domain.">"  );
    my @domainparts = split /\./, $domain ;
    my @rdn = ();
    foreach my $rdn ( @domainparts )
    {
        push @rdn, "dc=".$rdn;   
    }
    my $basedn = join ',', @rdn ;
    y2milestone("basedn: $basedn");
    $dbDefaults{'basedn'} = $basedn;
    $dbDefaults{'rootdn'} = "cn=admin,".$basedn;
    $dbDefaults{'pwenctype'} = "SSHA";
    $dbDefaults{'serviceEnabled'} = YaST::YCP::Boolean(0);
    $dbDefaults{'slpRegister'} = YaST::YCP::Boolean(0);
    return 1;
}

BEGIN { $TYPEINFO {ReadFromDefaults} = ["function", "boolean"]; }
sub ReadFromDefaults
{
    my $database = { 'type' => 'bdb',
                     'suffix' => $dbDefaults{'basedn'},
                     'rootdn' => $dbDefaults{'rootdn'},
                     'directory' => '/var/lib/ldap'
                   };
    my $cfgdatabase = { 'type' => 'config',
                     'rootdn' => 'cn=config',
                     'rootpw' => 'secret'
                   };

    @schema = ( "core", "cosine", "inetorgperson" );

    push @databases, ( $cfgdatabase, $database );

    SCR->Execute('.ldapserver.initGlobals' );
    SCR->Execute('.ldapserver.initSchema', \@schema );
    SCR->Execute('.ldapserver.initDatabases', \@databases );
    return 1;
}

BEGIN { $TYPEINFO {GetDatabaseList} = ["function", [ "list", [ "map" , "string", "string"] ] ]; }
sub GetDatabaseList
{
    y2milestone("GetDatabaseList");
    my $self = shift;
    my $ret = ();
    foreach my $db ( @databases )
    {
        my $tmp = { 'type' => $db->{'type'}, 
                'suffix' => $db->{'suffix'},
                'index' => $db->{'index'} };
        if (! $tmp->{'suffix'} )
        {
            $tmp->{'suffix'} = "unknown";
        }
        push @{$ret}, $tmp;
    }
    y2milestone(Data::Dumper->Dump([$ret]));
    return $ret
}

BEGIN { $TYPEINFO {GetDatabase} = ["function", [ "map" , "string", "string"], "integer" ]; }
sub GetDatabase
{
    my ($self, $index) = @_;
    y2milestone("GetDatabase ".$index);
    my $rc = SCR->Read(".ldapserver.database.{".$index."}" );
    y2milestone( "Database: ".Data::Dumper->Dump([$rc]) );
    return $rc;
}

BEGIN { $TYPEINFO {UpdateDatabase} = ["function", "boolean", "integer", [ "map" , "string", "string"] ]; }
sub UpdateDatabase 
{
    my ($self, $index, $changes) = @_;
    my $rc = SCR->Write(".ldapserver.database.{".$index."}", $changes);
    y2milestone( "Database: ".Data::Dumper->Dump([$rc]) );
    return $rc;

}

BEGIN { $TYPEINFO {HaveCommonServerCertificate} = ["function", "boolean" ]; }
sub HaveCommonServerCertificate
{
    my $self = shift;
    y2milestone("HaveCommonServerCertificate");

    if (SCR->Read(".target.size", '/etc/ssl/certs/YaST-CA.pem') <= 0)
    {
        y2milestone("YaST-CA.pem does not exists");
        return YaST::YCP::Boolean(0);
    }

    if (SCR->Read(".target.size", '/etc/ssl/servercerts/servercert.pem') <= 0 )
    {
        y2milestone("Common server certificate file does not exist");
        return YaST::YCP::Boolean(0);
    }
    if ( SCR->Read(".target.size", '/etc/ssl/servercerts/serverkey.pem') <= 0 )
    {
        y2milestone("Common server certificate key file does not exist");
        return YaST::YCP::Boolean(0);
    }
    return YaST::YCP::Boolean(1);
}

1;
# EOF
