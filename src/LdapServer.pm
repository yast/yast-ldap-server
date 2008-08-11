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

textdomain("ldap-server");
use strict;

use Data::Dumper;

use Digest::MD5 qw(md5_hex);
use Digest::SHA1 qw(sha1);
use MIME::Base64;
use X500::DN;
use ycp;
use YaST::YCP;
use YaPI;

our %TYPEINFO;

YaST::YCP::Import ("Progress");
YaST::YCP::Import ("SuSEFirewall");
YaST::YCP::Import ("Service");
YaST::YCP::Import ("SCR");

my %error = ( msg => undef, details => undef );
my $usingDefaults = 1;
my $configured = 0;
my $usesBackConfig = 0;
my $slapdConfChanged = 0;
my $overwriteConfig = 0;
my $serviceEnabled = 0;
my $serviceRunning = 1;
my $registerSlp = 0;
my $useLdapiForConfig = 0;
my %dbDefaults = ();

my $globals_initialized = 0;
my $use_ldapi_listener = 0;
my $use_ldaps_listener = 0;
my $use_ldap_listener = 0;
my $ldapi_interfaces = "";
my $ldaps_interfaces = "";
my $ldap_interfaces = "";

my @defaultIndexes = (
        { "name" => "objectclass",
          "eq" => YaST::YCP::Boolean(1) 
        },
        { "name" => "uidNumber",
          "eq" => YaST::YCP::Boolean(1) 
        },
        { "name" => "gidNumber",
          "eq" => YaST::YCP::Boolean(1)
        },
        { "name" => "member",
          "eq" => YaST::YCP::Boolean(1),
          "pres" => YaST::YCP::Boolean(1)
        },
        { "name" => "mail",
          "eq" => YaST::YCP::Boolean(1),
          "pres" => YaST::YCP::Boolean(1)
        },
        { "name" => "cn",
          "eq" => YaST::YCP::Boolean(1),
          "pres" => YaST::YCP::Boolean(1),
          "sub" => YaST::YCP::Boolean(1)
        },
        { "name" => "displayName",
          "eq" => YaST::YCP::Boolean(1),
          "pres" => YaST::YCP::Boolean(1),
          "sub" => YaST::YCP::Boolean(1)
        },
        { "name" => "uid",
          "eq" => YaST::YCP::Boolean(1),
          "pres" => YaST::YCP::Boolean(1),
          "sub" => YaST::YCP::Boolean(1)
        },
        { "name" => "sn",
          "eq" => YaST::YCP::Boolean(1),
          "pres" => YaST::YCP::Boolean(1),
          "sub" => YaST::YCP::Boolean(1)
        },
        { "name" => "givenName",
          "eq" => YaST::YCP::Boolean(1),
          "pres" => YaST::YCP::Boolean(1),
          "sub" => YaST::YCP::Boolean(1)
        }
    );

my @schema = ();

my @globalAcl = (
    { 'what' => 
        { 'filter' => undef,
          'attr' => undef,
          'dn' => 
            { 
              'style' => "base",
              'dn'    => ""
            }
        },
      'who' => 
      [
        { 'whotype' => "all",
          'whovalue' => undef,
          'level' => "read",
          'priv' => undef
        }
      ]
    },
    { 'what' => 
        { 'filter' => undef,
          'attr' => undef,
          'dn' => 
            { 'style' => "base",
              'dn'    => "cn=Subschema"
            }
        },
      'who' => 
      [
        { 'whotype' => "all",
          'whovalue' => undef,
          'level' => "read",
          'priv' => undef
        }
      ]
    }
);

my @added_databases = ();

##
 # Read all ldap-server settings
 # @return true on success
 #
BEGIN { $TYPEINFO{Read} = ["function", "boolean"]; }
sub Read {
    y2milestone("");
    SuSEFirewall->Read();

    my $progressItems = [ "Reading Startup Configuration", 
            "Reading Configuration Backend", 
            "Reading Configuration Data" ];
    Progress->New("Initializing LDAP Server Configuration", " ", 3, $progressItems, $progressItems, "");
    Progress->NextStage();

    my $serviceInfo = Service->FullInfo("ldap");
    y2milestone("Serviceinfo: ". Data::Dumper->Dump([$serviceInfo]));
    my $isRunning = ( defined $serviceInfo->{"started"}) && ($serviceInfo->{"started"} == 0); # 0 == "running"
    my $isEnabled = scalar(@{$serviceInfo->{"start"}}) > 0;
    $serviceEnabled = $isEnabled;
    $serviceRunning = $isRunning;
    y2milestone("IsRunning: " . $isRunning . " IsEnabled " . $isEnabled);

    $use_ldapi_listener = ( "yes" eq SCR->Read('.sysconfig.openldap.OPENLDAP_START_LDAPI') );
    $ldapi_interfaces = SCR->Read('.sysconfig.openldap.OPENLDAP_LDAPI_INTERFACES');

    $use_ldaps_listener = ( "yes" eq SCR->Read('.sysconfig.openldap.OPENLDAP_START_LDAPS') );
    $ldaps_interfaces = SCR->Read('.sysconfig.openldap.OPENLDAP_LDAPS_INTERFACES');
    
    $use_ldap_listener = ( "yes" eq SCR->Read('.sysconfig.openldap.OPENLDAP_START_LDAP') );
    $ldap_interfaces = SCR->Read('.sysconfig.openldap.OPENLDAP_LDAP_INTERFACES');
    
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
        }
        else
        {
            # check if configuration exists
            if (SCR->Read(".target.size", '/etc/openldap/slapd.d/cn=config.ldif') <= 0)
            {
                $slapdConfChanged = 0;
            }
            else
            {
                # LDAP Server not running. Can't read the configuration until
                # server started
                $slapdConfChanged = 1;
            }
#            y2milestone("Using slapcat to import configuration");
#            my $rc = SCR->Execute('.target.bash_output', 
#                    "/usr/sbin/slapcat -F /etc/openldap/slapd.d -b cn=config" );
#            y2milestone("slapcat result: ". Data::Dumper->Dump([$rc]));
#            SCR->Execute('.ldapserver.initFromLdif', $rc->{'stdout'});
#            $rc = SCR->Read('.ldapserver.databases' );
#            y2milestone("Databases: ". Data::Dumper->Dump([$rc]));
#            #$rc = SCR->Read('.ldapserver.global.tlsSettings' );
#            #y2milestone("tlsSettings: ". Data::Dumper->Dump([$rc]));
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

        y2milestone("ConfigModified: " . $slapdConfChanged);
    }
        
    Progress->Finish();
    return 1;
}

sub CreateBaseObjects()
{
    my $self = shift;
    foreach my $db (@added_databases )
    {
        y2milestone("creating base object for ". $db->{'suffix'} );
        my $object = X500::DN->ParseRFC2253($db->{'suffix'});
        if(! defined $object) {
            y2error("Error while parsing base dn");
            return 0;
        }
        my @attr = $object->getRDN($object->getRDNs()-1)->getAttributeTypes();
        my $val = $object->getRDN($object->getRDNs()-1)->getAttributeValue($attr[0]);
        if(!defined $attr[0] || !defined $val)
        {
            y2error("Error while extracting RDN values");
            return 0;
        }
        my $entry = {};
        
        if( lc($attr[0]) eq "ou") {
            $entry = {
                      "objectClass" => [ "organizationalUnit" ],
                      "ou" => $val,
                     }
        } elsif( lc($attr[0]) eq "o") {
            $entry = {
                      "objectClass" => [ "organization" ],
                      "o" => $val,
                     }
        } elsif( lc($attr[0]) eq "c") {
            if($val !~ /^\w{2}$/) {
                y2error("The countryName must be an ISO-3166 country 2-letter code.");
                return 0;
            }
            $entry = {
                      "objectClass" => [ "country" ],
                      "c" => $val,
                     }
        } elsif( lc($attr[0]) eq "l") {
            $entry = {
                      "objectClass" => [ "locality" ],
                      "l" => $val,
                     }
        } elsif( lc($attr[0]) eq "st") {
            $entry = {
                      "objectClass" => [ "locality" ],
                      "st" => $val,
                     }
        } elsif( lc($attr[0]) eq "dc") {
            $entry = {
                      "objectClass" => [ "organization", "dcObject" ],
                      "dc" => $val,
                      "o"  => $val,
                     }
        } else {
            y2error("First part of suffix must be c=, st=, l=, o=, ou= or dc=.");
            return 0;
        }

        if(! SCR->Execute(".ldap", {"hostname" => 'localhost',
                                    "port"     => 389})) {
            y2error("LDAP init failed");
            return 0;
        }
        
        my $ldapERR;
        
        if (! SCR->Execute(".ldap.bind", {"bind_dn" => $db->{'rootdn'},
                                          "bind_pw" => $db->{'rootpw'}}) ) {
            $ldapERR = SCR->Read(".ldap.error");
            y2error( "LDAP bind failed" );
            y2error( $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
            return 0;
        }
        
        if (! SCR->Write(".ldap.add", { dn => $db->{'suffix'} } , $entry)) {
            my $ldapERR = SCR->Read(".ldap.error");
            y2error("Can not add base entry.");
            y2error( $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
        }
        y2milestone("base entry added");
    }
    return 1;
}


##
 # Write all service-related settings (sysconfig, init.d)
 # @return true on success
 #
BEGIN { $TYPEINFO{WriteServiceSettings} = ["function", "boolean"]; }
sub WriteServiceSettings {
    my $self = shift;
    y2milestone("LdapServer::Write");
    my $ret = 1;
    # these changes might require a restart of slapd
    if ( $use_ldap_listener )
    {
        SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAP', 'yes');
    } 
    else
    {
        SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAP', 'no');
    }
    if ( $use_ldapi_listener )
    {
        SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPI', 'yes');
    } 
    else
    {
        SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPI', 'no');
    }
    if ( $use_ldaps_listener )
    {
        SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPS', 'yes');
    } 
    else
    {
        SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPS', 'no');
    }
    SuSEFirewall->Write();
    my $wasEnabled = Service->Enabled("ldap");
    if ( !$wasEnabled && $serviceEnabled  )
    {
        # service was disabled during this session, just disable the service
        # in the system, stop it and ignore any configuration changes.
        my $progressItems = [ _("Enabling LDAP Server"),
                _("Starting LDAP Server")
            ];
        Progress->New(_("Activating OpenLDAP Server"), "", 2, $progressItems, $progressItems, "");
        Progress->NextStage();
        Service->Enable("ldap");
        Progress->NextStage();
        Service->Start("ldap");
        Progress->Finish();
        return 0;
    }
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
    if ( ! $usesBackConfig || ! $slapdConfChanged || $overwriteConfig ) 
    {
        $overwriteConfig = 0;
        my $progressItems = [ _("Writing Startup Configuration"),
                _("Cleaning up config directory"),
                _("Creating Configuration"),
                _("Starting OpenLDAP Server"),
                _("Creating Base Objects") ];
        Progress->New("Writing OpenLDAP Server Configuration", "", 5, $progressItems, $progressItems, "");

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
                    $self->SetError( _("Error while populating the configurations database with \"slapadd\"."),
                            $rc->{'stderr'} );
                    y2error("Error during slapadd:" .$rc->{'stderr'});
                    return 0;
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
        if ( $use_ldaps_listener )
        {
            SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPS', 'yes');
        } 
        else
        {
            SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPS', 'no');
        }
        $rc = Service->Restart("ldap");
        if (! $rc )
        {
            y2error("Error while starting the LDAP service");
            $self->SetError( _("Starting the LDAP service failed.") );
            Progress->Finish();
            return 0;
        }
        Progress->NextStage();
        $rc = $self->CreateBaseObjects();
        if (! $rc )
        {
            y2error("Error while creating base objects");
            $self->SetError( _("Creating base objects failed.") );
            Progress->Finish();
            return 0;
        }
        Progress->Finish();
        SuSEFirewall->Write();
    } else {
        my $wasEnabled = Service->Enabled("ldap");
        if ( $wasEnabled && !$serviceEnabled  )
        {
            # service was disabled during this session, just disable the service
            # in the system, stop it and ignore any configuration changes.
            my $progressItems = [ _("Stopping LDAP Server"),
                    _("Disabling LDAP Server")
                ];
            Progress->New("De-activating OpenLDAP Server", "", 2, $progressItems, $progressItems, "");
            Progress->NextStage();
            Service->Disable("ldap");
            Progress->NextStage();
            Service->Stop("ldap");
            Progress->Finish();
            return 1;
        }

        # these changes might require a restart of slapd
        if ( $use_ldap_listener )
        {
            SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAP', 'yes');
        } 
        else
        {
            SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAP', 'no');
        }
        if ( $use_ldapi_listener )
        {
            SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPI', 'yes');
        } 
        else
        {
            SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPI', 'no');
        }
        if ( $use_ldaps_listener )
        {
            SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPS', 'yes');
        } 
        else
        {
            SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPS', 'no');
        }

        SuSEFirewall->Write();
        if( ! SCR->Execute('.ldapserver.commitChanges' ) )
        {
            my $err = SCR->Error(".ldapserver");
            y2error($err->{'summary'}." ".$err->{'description'});
            $self->SetError( $err->{'summary'}, $err->{'description'} );
            return 0;
        }
    }
    sleep(1);
    $configured = $ret;
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
    my $defaults = $self->CreateInitialDefaults();
    my $string;

    $string .= '<h2>'._("Startup Configuration").'</h2>'
            .'<p>'._("Start LDAP Server: ").'<code>'.($defaults->{'serviceEnabled'}->value?_("Yes"):_("No")).'</code></p>'
            .'<p>'._("Register at SLP Service: ").'<code>'.($defaults->{'slpRegister'}->value?_("Yes"):_("No")).'</code></p>'
            .'<h2>'._("Create initial Database with the following Parameters").'</h2>'
            .'<p>'._("Database Suffix: ").'<code>'.$defaults->{'suffix'}.'</code></p>'
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

BEGIN { $TYPEINFO{Configured} = ["function", "boolean"]; }
sub Configured
{
    return YaST::YCP::Boolean($configured);
}

BEGIN { $TYPEINFO{UseDefaults} = ["function", "boolean"]; }
sub UseDefaults
{
    return YaST::YCP::Boolean($usingDefaults);
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

BEGIN { $TYPEINFO {UseLdapiForConfig} = ["function", "boolean", "boolean"]; }
sub UseLdapiForConfig
{
    my $self = shift;
    $useLdapiForConfig = shift;
    return 1;
}

BEGIN { $TYPEINFO {ReadServiceEnabled} = ["function", "boolean"]; }
sub ReadServiceEnabled {
    y2milestone("ReadServiceEnabled $serviceEnabled");
    return $serviceEnabled;
}

BEGIN { $TYPEINFO {WriteServiceEnabled} = ["function", "boolean", "boolean"]; }
sub WriteServiceEnabled {
    my $self = shift;
    $serviceEnabled = shift;
    return 1;
}

BEGIN { $TYPEINFO {ReadServiceRunning} = ["function", "boolean"]; }
sub ReadServiceRunning {
    y2milestone("ReadServiceRunning $serviceRunning");
    return $serviceRunning;
}

BEGIN { $TYPEINFO {ReadSLPEnabled} = ["function", "boolean"]; }
sub ReadSLPEnabled {
    y2milestone("ReadSLPEnabled");
    return $registerSlp;
}

BEGIN { $TYPEINFO {WriteSLPEnabled} = ["function", "boolean", "boolean"]; }
sub WriteSLPEnabled {
    my $self = shift;
    y2milestone("WriteSlpEnabled");
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

BEGIN { $TYPEINFO {ReadError} = ["function", ["map", "string", "string"] ]; }
sub ReadError
{
    return \%error;
}

BEGIN { $TYPEINFO {ReadLogLevels} = ["function", [ "list", "string" ] ]; }
sub ReadLogLevels
{
    return  SCR->Read('.ldapserver.global.loglevel' );
}

BEGIN { $TYPEINFO {WriteLogLevels} = ["function", "boolean", [ "list", "string" ] ]; }
sub WriteLogLevels
{
    my $self = shift;
    my $lvls = shift;
    SCR->Write('.ldapserver.global.loglevel', $lvls );
    return 1;
}

BEGIN { $TYPEINFO {ReadAllowFeatures} = ["function", [ "list", "string" ] ]; }
sub ReadAllowFeatures
{
    return  SCR->Read('.ldapserver.global.allow' );
}

BEGIN { $TYPEINFO {ReadDisallowFeatures} = ["function", [ "list", "string" ] ]; }
sub ReadDisallowFeatures
{
    return  SCR->Read('.ldapserver.global.disallow' );
}

BEGIN { $TYPEINFO {WriteAllowFeatures} = ["function", "boolean", [ "list", "string" ] ]; }
sub WriteAllowFeatures
{
    my $self = shift;
    my $features = shift;
    SCR->Write('.ldapserver.global.allow', $features );
    return 1;
}

BEGIN { $TYPEINFO {WriteDisallowFeatures} = ["function", "boolean", [ "list", "string" ] ]; }
sub WriteDisallowFeatures
{
    my $self = shift;
    my $features = shift;
    SCR->Write('.ldapserver.global.disallow', $features );
    return 1;
}

BEGIN { $TYPEINFO {ReadTlsConfig} = ["function", [ "map", "string", "any" ] ]; }
sub ReadTlsConfig
{
    return SCR->Read('.ldapserver.global.tlsSettings' );
}

BEGIN { $TYPEINFO {WriteTlsConfig} = ["function", "boolean", [ "map", "string", "any" ] ]; }
sub WriteTlsConfig
{
    my $self = shift;
    my $tls = shift;
    if ( $tls->{'tls_active'} )
    {
        if ( SCR->Read(".target.size", $tls->{"caCertFile"}) <= 0)
        {
            $self->SetError( _("CA Certificate File does not exist"), "");
            return 0;
        }
        if ( SCR->Read(".target.size", $tls->{"certFile"}) <= 0)
        {
            $self->SetError( _("Certificate File does not exist"), "" );
            return 0;
        }
        if ( SCR->Read(".target.size", $tls->{"certKeyFile"}) <= 0)
        {
            $self->SetError( _("Certificate Key File does not exist"), "");
            return 0;
        }

        if ( SCR->Execute(".target.bash", 
                               "/usr/bin/setfacl -m u:ldap:r ".$tls->{'certKeyFile'}) )
        {
            $self->SetError(_("Can not set a filesystem acl on the private key"),
                                   "setfacl -m u:ldap:r ".$tls->{'certKeyFile'}." failed.\n".
                                   "Do you have filesystem acl support disabled?" );
            return 0;
        }
    }
    my $rc = SCR->Write('.ldapserver.global.tlsSettings', $tls );
    return 1;
}

BEGIN { $TYPEINFO {WriteTlsConfigCommonCert} = ["function", "boolean" ]; }
sub WriteTlsConfigCommonCert
{
    my $self = shift;
    my $ret = SCR->Execute(".target.bash", 
                           "/usr/bin/setfacl -m u:ldap:r /etc/ssl/servercerts/serverkey.pem");
    if($ret != 0) {
        $self->SetError(_("Can not set a filesystem acl on the private key"),
                               "setfacl -m u:ldap:r /etc/ssl/servercerts/serverkey.pem failed.\n".
                               "Do you have filesystem acl support disabled?" );
        return 0;
    }

    my $tlsSettings = {
                "certKeyFile"  => "/etc/ssl/servercerts/serverkey.pem",
                "certFile"     => "/etc/ssl/servercerts/servercert.pem",
                "caCertFile"   => "/etc/ssl/certs/YaST-CA.pem",
                "caCertDir"    => "",
                "crlFile"      => "",
                "crlCheck"     => 0,
                "verifyClient" => 0
    };
    return $self->WriteTlsConfig( $tlsSettings );
}

BEGIN { $TYPEINFO {MigrateSlapdConf} = ["function", "boolean"]; }
sub MigrateSlapdConf
{
    my $self = shift;
    my $progressItems = [ _("Cleaning up directory for config database"),
            _("Converting slapd.conf to config database"), 
            _("Switching startup configuration to use config database"),
            _("Restarting LDAP Server") ]; 
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
    if ( $useLdapiForConfig )
    {
        $rc = SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPI', 'yes');
        if ( ! $rc )
        {
            y2error("Error while enabling LDAPI listener");
            $self->SetError( _("Enabling LDAPI listener failed.") );
            Progress->Finish();
            return 0;
        }
        $rc = SCR->Execute('.ldapserver.addRootSaslRegexp');
        if ( ! $rc )
        {
            y2error("Error while creating SASL Auth mapping for \"root\".");
            $self->SetError( _("Enabling LDAPI listener failed.") );
            Progress->Finish();
            return 0;
        }
    }
    # FIXME:
    # Explicit cache flush, see bnc#350581 for details
    SCR->Write(".sysconfig.openldap", undef);
    Progress->NextStage();
    $rc = Service->Restart("ldap");
    if (! $rc )
    {
        y2error("Error while starting the LDAP service");
        $self->SetError( _("Starting the LDAP service failed.") );
        Progress->Finish();
        return 0;
    }
    Progress->Finish();
    return 1;
}

BEGIN { $TYPEINFO {CreateInitialDefaults} = ["function", [ "map", "string", "any"] ]; }
sub CreateInitialDefaults
{
    y2milestone("CreateInitialDefaults");
    my $self = shift;
    if ( ! keys(%dbDefaults ) ) {
        $self->InitDbDefaults();
    }
    y2milestone(Data::Dumper->Dump([\%dbDefaults]));
    $usingDefaults = 1;
    $overwriteConfig = 1;
    return \%dbDefaults;
}

BEGIN { $TYPEINFO {SetInitialDefaults} = ["function", "boolean", [ "map", "string", "any" ] ]; }
sub SetInitialDefaults
{
    my $self = shift;
    my $defaults = shift;
    $defaults->{'serviceEnabled'} =  YaST::YCP::Boolean($defaults->{'serviceEnabled'});
    $defaults->{'slpRegister'} =  YaST::YCP::Boolean($defaults->{'slpRegister'});
    $defaults->{'checkpoint'} = [ YaST::YCP::Integer($defaults->{'checkpoint'}->[0]),
                                  YaST::YCP::Integer($defaults->{'checkpoint'}->[1]) ];
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
    y2milestone("suffix: $basedn");
    $dbDefaults{'suffix'} = $basedn;
    $dbDefaults{'directory'} = "/var/lib/ldap";
    $dbDefaults{'rootdn'} = "cn=admin,".$basedn;
    $dbDefaults{'rootpw'} = "";
    $dbDefaults{'rootpw_clear'} = "";
    $dbDefaults{'pwenctype'} = "SSHA";
    $dbDefaults{'entrycache'} = 10000;
    $dbDefaults{'idlcache'} = 30000;
    $dbDefaults{'checkpoint'} = [ YaST::YCP::Integer(1024),
            YaST::YCP::Integer(5) ];
    
    $dbDefaults{'defaultIndex'} = YaST::YCP::Boolean(1);
    $dbDefaults{'serviceEnabled'} = YaST::YCP::Boolean(0);
    $dbDefaults{'slpRegister'} = YaST::YCP::Boolean(0);
    return 1;
}

BEGIN { $TYPEINFO {InitGlobals} = ["function", "boolean"]; }
sub InitGlobals
{
    my $self = shift;
    if ( ! $globals_initialized )
    {
        SCR->Execute('.ldapserver.initGlobals' );
        if(! $self->HaveCommonServerCertificate() )
        {
            y2milestone( _("Common server certificate not available. StartTLS is disabled.") );
        }
        else
        {
            $self->WriteTlsConfigCommonCert();
            $self->WriteProtocolListenerEnabled("ldaps", 1);
        }
        $globals_initialized = 1;
    }
    return 1;
}

BEGIN { $TYPEINFO {ReadFromDefaults} = ["function", "boolean"]; }
sub ReadFromDefaults
{
    my $self = shift;
    
    my $pwHash =  $self->HashPassword($dbDefaults{'pwenctype'}, $dbDefaults{'rootpw_clear'} );
    my $database = { 'type' => 'hdb',
                     'suffix' => $dbDefaults{'suffix'},
                     'rootdn' => $dbDefaults{'rootdn'},
                     'rootpw' => $pwHash,
                     'directory' => '/var/lib/ldap',
                     'entrycache' => YaST::YCP::Integer($dbDefaults{'entrycache'}),
                     'idlcache' => YaST::YCP::Integer($dbDefaults{'idlcache'}),
                     'checkpoint' => $dbDefaults{'checkpoint'} };
    my $cfgdatabase = { 'type' => 'config',
                        'rootdn' => 'cn=config' };
    my $frontenddb = { 'type' => 'frontend',
                       'access' => [
                            'to dn.base="" by * read',
                            'to dn.base="cn=Subschema" by * read', 
                            'to attrs=userPassword,userPKCS12 by self write by * auth', 
                            # 'to attrs=shadowLastChange by self write by * read', 
                            'to * by * read'
                        ]
                      };

    $self->InitGlobals();
    SCR->Execute('.ldapserver.initSchema' );
    my $rc = SCR->Write(".ldapserver.schema.addFromLdif", "/etc/openldap/schema/core.ldif" );
    if ( ! $rc ) {
        my $err = SCR->Error(".ldapserver");
        y2error("Adding Schema failed: ".$err->{'summary'}." ".$err->{'description'});
        $self->SetError( $err->{'summary'}, $err->{'description'} );
        return $rc;
    }
    $rc = SCR->Write(".ldapserver.schema.addFromLdif", "/etc/openldap/schema/cosine.ldif" );
    if ( ! $rc ) {
        my $err = SCR->Error(".ldapserver");
        y2error("Adding Schema failed: ".$err->{'summary'}." ".$err->{'description'});
        $self->SetError( $err->{'summary'}, $err->{'description'} );
        return $rc;
    }
    $rc = SCR->Write(".ldapserver.schema.addFromLdif", "/etc/openldap/schema/inetorgperson.ldif" );
    if ( ! $rc ) {
        my $err = SCR->Error(".ldapserver");
        y2error("Adding Schema failed: ".$err->{'summary'}." ".$err->{'description'});
        $self->SetError( $err->{'summary'}, $err->{'description'} );
        return $rc;
    }
    $rc = SCR->Write(".ldapserver.schema.addFromSchemafile", "/etc/openldap/schema/rfc2307bis.schema" );
    if ( ! $rc ) {
        my $err = SCR->Error(".ldapserver");
        y2error("Adding Schema failed: ".$err->{'summary'}." ".$err->{'description'});
        $self->SetError( $err->{'summary'}, $err->{'description'} );
        return $rc;
    }

    SCR->Execute('.ldapserver.initDatabases', [ $frontenddb, $cfgdatabase, $database ] );
    if ( $dbDefaults{'defaultIndex'} == 1 )
    {
        foreach my $idx ( @defaultIndexes )
        {
            $self->ChangeDatabaseIndex(1, $idx );
        }
    }
    push @added_databases, { suffix => $dbDefaults{'suffix'}, 
                             rootdn => $dbDefaults{'rootdn'},
                             rootpw => $dbDefaults{'rootpw_clear'} };
    $usingDefaults = 0;
    return 1;
}

BEGIN { $TYPEINFO {ReadDatabaseList} = ["function", [ "list", [ "map" , "string", "string"] ] ]; }
sub ReadDatabaseList
{
    y2milestone("ReadDatabaseList");
    my $self = shift;
    my $ret = ();
    my $rc = SCR->Read('.ldapserver.databases');
    foreach my $db ( @{$rc} )
    {
        my $tmp = { 'type' => $db->{'type'}, 
                'suffix' => $db->{'suffix'},
                'index' => $db->{'index'} };
        push @{$ret}, $tmp;
    }
    y2milestone(Data::Dumper->Dump([$ret]));
    return $ret
}

BEGIN { $TYPEINFO {ReadDatabase} = ["function", [ "map" , "string", "string"], "integer" ]; }
sub ReadDatabase
{
    my ($self, $index) = @_;
    y2milestone("ReadDatabase ".$index);
    my $rc = SCR->Read(".ldapserver.database.{".$index."}" );
    y2milestone( "Database: ".Data::Dumper->Dump([$rc]) );
    return $rc;
}

BEGIN { $TYPEINFO {ReadDatabaseIndexes} = ["function", [ "map" , "string", [ "map", "string", "boolean" ] ], "integer" ]; }
sub ReadDatabaseIndexes
{
    my ($self, $index) = @_;
    y2milestone("ReadDatabaseIndexes ".$index);
    my $rc = SCR->Read(".ldapserver.database.{".$index."}.indexes" );
    y2milestone( "Indexes: ".Data::Dumper->Dump([$rc]) );
    return $rc;
}

BEGIN { $TYPEINFO {ChangeDatabaseIndex} = ["function", "boolean" , "integer", ["map", "string", "any" ] ]; }
sub ChangeDatabaseIndex
{
    my ($self, $dbIndex, $newIdx ) = @_;
    y2milestone("ChangeDatabaseIndex: ".Data::Dumper->Dump([$newIdx]) );
    $newIdx->{'pres'} = YaST::YCP::Boolean($newIdx->{'pres'});
    $newIdx->{'eq'} = YaST::YCP::Boolean($newIdx->{'eq'});
    $newIdx->{'sub'} = YaST::YCP::Boolean($newIdx->{'sub'});
    my $rc = SCR->Write(".ldapserver.database.{".$dbIndex."}.index", $newIdx );
    return $rc;
}

BEGIN { $TYPEINFO {ReadOverlayList} = ["function", [ "list", [ "map" , "string", "string"] ], "integer" ]; }
sub ReadOverlayList
{
    my ($self, $index) = @_;
    y2milestone("ReadOverlayList ", $index);
    my $rc = SCR->Read(".ldapserver.database.{".$index."}.overlays" );
    y2milestone( "Overlays: ".Data::Dumper->Dump([$rc]) );
    return $rc;
}

BEGIN { $TYPEINFO {ReadPpolicyOverlay} = ["function", [ "map" , "string", "any" ], "integer" ]; }
sub ReadPpolicyOverlay
{
    my ($self, $index) = @_;
    y2milestone("ReadPpolicyOverlay ", $index);
    my $rc = SCR->Read(".ldapserver.database.{".$index."}.ppolicy" );
    y2milestone( "Ppolicy: ".Data::Dumper->Dump([$rc]) );
    if ( defined $rc->{'hashClearText'} )
    {
        $rc->{'hashClearText'} = YaST::YCP::Boolean($rc->{'hashClearText'});
    }
    if ( defined $rc->{'useLockout'} )
    {
        $rc->{'useLockout'} = YaST::YCP::Boolean($rc->{'useLockout'});
    }
    return $rc;
}

BEGIN { $TYPEINFO {AddPasswordPolicy} = ["function", "boolean" , "integer", ["map", "string", "any" ] ]; }
sub AddPasswordPolicy
{
    my ($self, $dbIndex, $ppolicy ) = @_;
    y2milestone("AddPasswordPolicy: ".Data::Dumper->Dump([$ppolicy])." ". scalar(keys %{$ppolicy}) );

    if ( 0 < scalar(keys %{$ppolicy}) )
    {
        $ppolicy->{'hashClearText'} = YaST::YCP::Boolean($ppolicy->{'hashClearText'});
        $ppolicy->{'useLockout'} = YaST::YCP::Boolean($ppolicy->{'useLockout'});
        
        # slapo-ppolicy requires ppolicy schema to be loaded
        my $schema = $self->ReadSchemaList();
        if ( ! grep( /^ppolicy$/, @{$schema} ) )
        {
            my $rc = $self->AddSchemaToSchemaList("/etc/openldap/schema/ppolicy.schema");
            if ( ! $rc )
            {
                return $rc;
            }
        }
    }

    if ( ! SCR->Write(".ldapserver.database.{".$dbIndex."}.ppolicy", $ppolicy ) ) {
        my $err = SCR->Error(".ldapserver");
        $self->SetError( $err->{'summary'}, $err->{'description'} );
        return YaST::YCP::Boolean(0);
    } else {
        return YaST::YCP::Boolean(1);
    }
}

BEGIN { $TYPEINFO {ReadSchemaList} = ["function", [ "list" , "string"] ]; }
sub ReadSchemaList
{
    my $self = @_;
    y2milestone("ReadSchemaList ");
    my $rc = SCR->Read(".ldapserver.schemaList" );
    y2milestone( "SchemaList: ".Data::Dumper->Dump([$rc]) );
    return $rc;
}

BEGIN { $TYPEINFO {AddSchemaToSchemaList} = ["function", "boolean", "string" ]; }
sub AddSchemaToSchemaList
{
    my ($self, $file) = @_;

    my $rc = SCR->Write(".ldapserver.schema.addFromSchemafile", $file);
    if ( ! $rc ) {
        my $err = SCR->Error(".ldapserver");
        $self->SetError( $err->{'summary'}, $err->{'description'} );
    }
    return $rc;
}

BEGIN { $TYPEINFO {AddLdifToSchemaList} = ["function", "boolean", "string" ]; }
sub AddLdifToSchemaList
{
    my ($self, $file) = @_;

    my $rc = SCR->Write(".ldapserver.schema.addFromLdif", $file);
    if ( ! $rc ) {
        my $err = SCR->Error(".ldapserver");
        $self->SetError( $err->{'summary'}, $err->{'description'} );
    }
    return $rc;
}

BEGIN { $TYPEINFO {RemoveFromSchemaList} = ["function", "boolean", "string" ]; }
sub RemoveFromSchemaList
{
    my ($self, $name) = @_;

    my $rc = SCR->Write(".ldapserver.schema.remove", $name);

    return $rc;
}


BEGIN { $TYPEINFO {AddDatabase} = ["function", "boolean", "integer", [ "map" , "string", "any"], "boolean" ]; }
sub AddDatabase
{
    my ($self, $index, $db, $createDir) = @_;
    y2milestone("AddDatabase: ".Data::Dumper->Dump([$db]) );
    if ( $createDir )
    {
        my $ret = SCR->Execute(".target.bash", "mkdir -m 0700 -p ".$db->{directory});
        if( ( $ret ) && ( ! defined  SCR->Read(".target.dir", $db->{directory}) ) ) {
            $self->SetError(_("Could not create directory."), "");
            return 0;
        }
        my $owner = SCR->Read('.sysconfig.openldap.OPENLDAP_USER');
        my $group = SCR->Read('.sysconfig.openldap.OPENLDAP_GROUP');
        $ret = SCR->Execute(".target.bash", "chown ".$owner.":".$group." ".$db->{directory});
        if ( $ret ) {
            $self->SetError(_("Could adjust ownership of database directory."), "");
            return 0;
        }
    }
    my $rc;
    $db->{'rootpw'} = $self->HashPassword($db->{'pwenctype'}, $db->{'rootpw_clear'} );
    if ( $index == 0 )
    {
        # calculate new database index
        $index =  (scalar(@{$self->ReadDatabaseList()} )) - 1;
    }
    $rc = SCR->Write(".ldapserver.database.new.{$index}", $db);
    if(! $rc ) {
        my $err = SCR->Error(".ldapserver");
        y2error("Adding Database failed: ".$err->{'summary'}." ".$err->{'description'});
        $self->SetError( $err->{'summary'}, $err->{'description'} );
        return 0;
    }
    # default indexing
    foreach my $idx ( @defaultIndexes )
    {
        $self->ChangeDatabaseIndex($index, $idx );
    }

    # add some default ACLs
    my @acls = ('to dn.subtree="'. $db->{'suffix'} .'" attrs=userPassword by self write by * auth', 
                # 'to attrs=shadowLastChange by self write by * read', 
                'to dn.subtree="'. $db->{'suffix'} .'" by * read');
    foreach my $acl (@acls )
    {
        $rc = SCR->Write(".ldapserver.database.{$index}.access", $acl );
        if(! $rc ) {
            my $err = SCR->Error(".ldapserver");
            y2error("Adding default ACLs failed: ".$err->{'summary'}." ".$err->{'description'});
            $self->SetError( $err->{'summary'}, $err->{'description'} );
            return 0;
        }
    }

    # add some defaults to DB_CONFIG
    my $dbconfig = [
        "set_cachesize 0 15000000 1",
        "set_lg_regionmax 262144",
        "set_lg_bsize 2097152",
        "set_flags DB_LOG_AUTOREMOVE"
    ];
    $rc = SCR->Write(".ldapserver.database.{$index}.dbconfig", $dbconfig );
    if(! $rc ) {
        my $err = SCR->Error(".ldapserver");
        y2error("Adding DB_CONFIG failed: ".$err->{'summary'}." ".$err->{'description'});
        $self->SetError( $err->{'summary'}, $err->{'description'} );
        return 0;
    }
    return 1;
}

BEGIN { $TYPEINFO {UpdateDatabase} = ["function", "boolean", "integer", [ "map" , "string", "string"] ]; }
sub UpdateDatabase 
{
    my ($self, $index, $changes) = @_;
    y2milestone( "UpdateDatabase: ".Data::Dumper->Dump([$changes]) );
    my $rc = SCR->Write(".ldapserver.database.{".$index."}", $changes);
    y2milestone( "result: ".Data::Dumper->Dump([$rc]) );
    return $rc;

}
##
 # Get all ldap-server settings from the first parameter
 # (For use by autoinstallation.)
 # @param hashalgorithm a string defining the hashing algorithm (can be one of
 #        "CRYPT", "SMD5", "SHA", "SSHA" and "PLAIN"
 # @param cleartext the cleartext password
 # @return The hashed password value (Format: {hashmethod}hashedpassword )
 #
BEGIN { $TYPEINFO {HashPassword} = ["function", "string", "string", "string" ] ; }
sub HashPassword
{
    my ($self, $hashAlgo, $cleartext) = @_;
    my $hashed;
    if( !grep( ($_ eq $hashAlgo), ("CRYPT", "SMD5", "SHA", "SSHA", "PLAIN") ) ) {
        # unsupported password hash
        return "";
    }

    if( $hashAlgo eq "CRYPT" ) {
        my $salt =  pack("C2",(int(rand 26)+65),(int(rand 26)+65));
        $hashed = crypt $cleartext,$salt;
        $hashed = "{CRYPT}".$hashed;
    } elsif( $hashAlgo eq "SMD5" ) {
        my $salt =  pack("C5",(int(rand 26)+65),(int(rand 26)+65),(int(rand 26)+65),
                         (int(rand 26)+65), (int(rand 26)+65));
        my $ctx = new Digest::MD5();
        $ctx->add($cleartext);
        $ctx->add($salt);
        $hashed = "{SMD5}".encode_base64($ctx->digest.$salt, "");
    } elsif( $hashAlgo eq "SHA"){
        my $digest = sha1($cleartext);
        $hashed = "{SHA}".encode_base64($digest, "");
    } elsif( $hashAlgo eq "SSHA"){
        my $salt =  pack("C5",(int(rand 26)+65),(int(rand 26)+65),(int(rand 26)+65),
                         (int(rand 26)+65), (int(rand 26)+65));
        my $digest = sha1($cleartext.$salt);
        $hashed = "{SSHA}".encode_base64($digest.$salt, "");
    } else {
        $hashed = $cleartext;
    }
    return $hashed;
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

BEGIN { $TYPEINFO {ReadProtocolListenerEnabled} = ["function", "boolean", "string" ]; }
sub ReadProtocolListenerEnabled
{
    my ( $self, $protocol ) = @_;
    y2milestone("ReadProtocolListenerEnabled $protocol (ldapi $use_ldapi_listener, ldaps $use_ldaps_listener, ldap $use_ldap_listener)");
    if ( $protocol eq "ldap" )
    {
        return $use_ldap_listener;
    }
    elsif ( $protocol eq "ldapi" )
    {
        return $use_ldapi_listener;
    }
    elsif ( $protocol eq "ldaps" )
    {
        return $use_ldaps_listener;
    }
    else
    {
        return 0;
    }
}

BEGIN { $TYPEINFO {WriteProtocolListenerEnabled} = ["function", "boolean", "string", "boolean" ]; }
sub WriteProtocolListenerEnabled
{
    my ( $self, $protocol, $enabled ) = @_;
    y2milestone("WriteProtocolListenerEnabled $protocol $enabled");
    if ( $protocol eq "ldap" )
    {
        $use_ldap_listener = $enabled;
    }
    elsif ( $protocol eq "ldapi" )
    {
        $use_ldapi_listener = $enabled;
    }
    elsif ( $protocol eq "ldaps" )
    {
        $use_ldaps_listener = $enabled;
    }
    else
    {
        return 0;
    }
    return 1;
}
1;
# EOF
