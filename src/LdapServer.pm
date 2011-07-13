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
YaST::YCP::Import ("Hostname");

my %error = ( msg => undef, details => undef );
my $ssl_check_command = "/usr/lib/YaST2/bin/ldap-server-ssl-check";
my $usingDefaults = 1;
my $fqdn = "";
my $readConfig = 0;
my $restartRequired = 0;
my $configured = 0;
my $usesBackConfig = 0;
my $slapdConfChanged = 0;
my $overwriteConfig = 0;
my $setupSyncreplSlave = 0;
my $setupSyncreplMaster = 0;
my $setupMirrorMode = 0;
my $modeInstProposal = 0;
my $serviceEnabled = 0;
my $serviceRunning = 1;
my $registerSlp = 0;
my $useLdapiForConfig = 0;
my %dbDefaults = ();

my $ldapconf_base = "";
my $write_ldapconf = 0;

my $globals_initialized = 0;
my $use_ldapi_listener = 0;
my $use_ldaps_listener = 0;
my $use_ldap_listener = 0;
my $ldapi_interfaces = "";
my $ldaps_interfaces = "";
my $ldap_interfaces = "";
my $defaultDbAcls = [
        {
            'target' => {
                        'attrs'  => "userPassword"
                    },
            'access' => [
                    {
                        'level' => 'write',
                        'type'  => 'self'
                    },{
                        'type'  => '*',
                        'level' => 'auth'
                    }
                ]
        },{
            'target' => {
                        'attrs' => "shadowLastChange"
                    },
            'access' => [
                    {
                        'type'  => 'self',
                        'level' => 'write'
                    },{
                        'type'  => '*',
                        'level' => 'read'
                    }
                ]
        },{
            'target' => {
                        'attrs' => "userPKCS12"
                    },
            'access' => [
                    {
                        'type'  => 'self',
                        'level' => 'read'
                    },{
                        'type'  => '*',
                        'level' => 'none'
                    }
                ]
        },{
            'target' => {},
            'access' => [
                    {
                        'type'  => '*',
                        'level' => 'read'
                    }
                ]
        }
    ];

my $defaultGlobalAcls = [
        {
            'target' => {
                        'dn' => {
                            'style' => 'base',
                            'value' => ''
                        }
                    },
            'access' => [
                    {
                        'type'  => '*',
                        'level' => 'read'
                    }
                ]
        },{
            'target' => {
                        'dn' => {
                            'style' => 'base',
                            'value' => 'cn=Subschema'
                        }
                    },
            'access' => [
                    {
                        'type'  => '*',
                        'level' => 'read'
                    }
                ]
        }
    ];
my $defaultIndexes = [
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
        },
        { "name" => "memberUid",
          "eq" => YaST::YCP::Boolean(1),
        },
        { "name" => "mail",
          "eq" => YaST::YCP::Boolean(1),
        },
        { "name" => "cn",
          "eq" => YaST::YCP::Boolean(1),
          "sub" => YaST::YCP::Boolean(1)
        },
        { "name" => "displayName",
          "eq" => YaST::YCP::Boolean(1),
          "sub" => YaST::YCP::Boolean(1)
        },
        { "name" => "uid",
          "eq" => YaST::YCP::Boolean(1),
          "sub" => YaST::YCP::Boolean(1)
        },
        { "name" => "sn",
          "eq" => YaST::YCP::Boolean(1),
          "sub" => YaST::YCP::Boolean(1)
        },
        { "name" => "givenName",
          "eq" => YaST::YCP::Boolean(1),
          "sub" => YaST::YCP::Boolean(1)
        }
    ];

my @schema = ();

my @added_databases = ();

# contains dn/password pairs to mapped to database suffix,
# can be used to bind against the databases
my $auth_info = {};

# contains a hash, keyed by database suffixed that contains
# hashes of the password policy DNs and and objects
my $ppolicy_objects = {};

my $syncreplaccount = {};
my $syncreplbaseconfig = {};
my $masterldif = "";

##
 # Read all ldap-server settings
 # @return true on success
 #
BEGIN { $TYPEINFO{Read} = ["function", "boolean"]; }
sub Read {
    my $self = shift;
    SuSEFirewall->Read();

    my $progressItems = [ _("Reading Startup Configuration"), 
            _("Reading Configuration Backend"), 
            _("Reading Configuration Data") ];
    Progress->New(_("Initializing LDAP Server Configuration"), " ", 3, $progressItems, $progressItems, "");
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
    $registerSlp = ( "yes" eq SCR->Read('.sysconfig.openldap.OPENLDAP_REGISTER_SLP') );
    
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
            if ( ! SCR->Execute('.ldapserver.init' ) )
            {
                my $err = SCR->Error(".ldapserver");
                $self->SetError( _("Error while initializing the configuration.\nIs the LDAPI listener enabled?"), $err->{'description'} );
                return 0;
            }
            my $rc = SCR->Read('.ldapserver.databases');
            $usingDefaults = 0;
            $readConfig = 1;
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

    # Read base-dn from /etc/openldap/ldap.conf
    my $base_list = SCR->Read(".etc.ldap_conf.value.\"/etc/openldap/ldap.conf\".base" );
    $ldapconf_base = $base_list->[0];
        
    Progress->Finish();
    return 1;
}

BEGIN { $TYPEINFO {WriteModeInstProposal} = ["function",  "boolean", "boolean"]; }
sub WriteModeInstProposal
{
    my ( $self, $value ) = @_;
    $modeInstProposal=$value;
    return 1;
}

BEGIN { $TYPEINFO {ReadModeInstProposal} = ["function",  "boolean" ]; }
sub ReadModeInstProposal
{
    return $modeInstProposal;
}

##
 # @return the base DN that is currently set in /etc/openldap/ldap.conf
 #
BEGIN { $TYPEINFO{ReadLdapconfBase} = ["function", "string"]; }
sub ReadLdapconfBase()
{
    return $ldapconf_base;
}

##
 # @return the full qualified hostname of the machine or "" if not set
 #
BEGIN { $TYPEINFO{ReadHostnameFQ} = ["function", "string"]; }
sub ReadHostnameFQ()
{
    if ( $fqdn eq "" )
    {
        my $rc = SCR->Execute( '.target.bash_output', "/bin/hostname -f" );
        if ( $rc->{'stdout'} eq "" )
        {
            y2milestone("could determine fqdn, hostname -f returned: ". $rc->{'stderr'} );
        }
        else
        {
            $fqdn = $rc->{'stdout'};
            chomp($fqdn);
        }
    }
    return $fqdn;
}

##
 # @return Set base DN that shoudl we written to /etc/openldap/ldap.conf
 #
BEGIN { $TYPEINFO{WriteLdapConfBase} = ["function", "boolean", "string"]; }
sub WriteLdapConfBase()
{
    my ($self, $basedn) = @_;
    y2debug("WriteLdapConfBase: $basedn");
    if ( $basedn ne "" )
    {
        $ldapconf_base = $basedn;
        $write_ldapconf = 1;
    }
    return 1;
}

sub CreateBaseObjects()
{
    my $self = shift;
    foreach my $db (@added_databases )
    {
        y2milestone("creating base object for ". $db );
        my $object = X500::DN->ParseRFC2253($db);
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
        my $db_auth = $self->ReadAuthInfo( $db );
        if ( keys( %$db_auth ) )
        {
            if (! SCR->Execute(".ldap.bind", {"bind_dn" => $db_auth->{'bind_dn'},
                                              "bind_pw" => $db_auth->{'bind_pw'}}) ) {
                $ldapERR = SCR->Read(".ldap.error");
                y2error( "LDAP bind failed" );
                y2error( $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
                return 0;
            }
            if (! SCR->Write(".ldap.add", { dn => $db } , $entry)) {
                my $ldapERR = SCR->Read(".ldap.error");
                y2error("Can not add base entry.");
                y2error( $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
            }
            y2milestone("base entry added");
        }
        else
        {
            y2milestone("Authentication information for database $db unavailable");
        }
    }
    return 1;
}

BEGIN { $TYPEINFO{WriteSyncReplAccount} = ["function", "boolean", ["map", "string", "string"] ]; }
sub WriteSyncReplAccount()
{
    my ( $self, $account ) = @_;
    y2milestone("WriteSyncReplAccount()");
    $syncreplaccount->{'syncdn'} = $account->{'dn'};
    $syncreplaccount->{'syncpw'} = $account->{'pw'};
    $syncreplaccount->{'syncpw_hash'} = $self->HashPassword("SSHA", $account->{'pw'} );
    $syncreplaccount->{'basedn'} = $account->{'dbsuffix'};

    return 1;
}

sub CreateSyncReplAccount()
{
    my $self = shift;
    y2milestone("CreateSyncReplAccount()");
    if (defined $syncreplaccount->{'syncdn'} && defined $syncreplaccount->{'syncpw'} &&
        defined $syncreplaccount->{'basedn'} && defined $syncreplaccount->{'syncpw_hash'})
    {
        my $db_auth = $self->ReadAuthInfo(  $syncreplaccount->{'basedn'} );
        if ( keys( %$db_auth ) )
        {
            my $object = X500::DN->ParseRFC2253( $syncreplaccount->{'syncdn'} );
            my $suffixDn = X500::DN->ParseRFC2253( $syncreplaccount->{'basedn'} );
            if(! defined $object) {
                y2error("Error while parsing dn");
                return 0;
            }
            if ( $object->getRDNs() > ( $suffixDn->getRDNs()+2 ) )
            {
                y2error("Error while parsing dn");
                return 0;
            }
            my @attr = $object->getRDN($object->getRDNs()-2)->getAttributeTypes();
            my $val = $object->getRDN($object->getRDNs()-2)->getAttributeValue($attr[0]);
            my $parententry = {};
            if( lc($attr[0]) eq "ou") {
                $parententry = {
                      "objectClass" => [ "organizationalUnit" ],
                      "ou" => $val,
                }
            }
            else
            {
                y2error("Cannot create ".$attr[0]." object");
                return 0;
            }
            my $parentdn = $attr[0]."=".$val.",".$syncreplaccount->{'basedn'};
            my $syncaccountentry = {
                    "objectclass" => [ "account", "simpleSecurityObject" ],
                    "uid" => "syncrepl",
                    "userPassword" => $syncreplaccount->{'syncpw_hash'},
                    "pwdPolicySubentry" => "" # To make sure that no password policies are applied 
                                              # to this entry!
                    };
            my $ldapERR=undef;

            if (! SCR->Execute(".ldap.bind", {"bind_dn" => $db_auth->{'bind_dn'},
                                              "bind_pw" => $db_auth->{'bind_pw'}}) ) {
                $ldapERR = SCR->Read(".ldap.error");
                y2error( "LDAP bind failed" );
                y2error( $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
                return 0;
            }
            if (! SCR->Write(".ldap.add", { dn => $parentdn } , $parententry)) {
                my $ldapERR = SCR->Read(".ldap.error");
                y2error("Can not add base entry.");
                y2error( $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
                if ( $ldapERR->{'code'} != 68 ) # already exists
                {
                    return 0;
                }
            }
            if (! SCR->Write(".ldap.add", { dn => $syncreplaccount->{'syncdn'} } , $syncaccountentry)) {
                my $ldapERR = SCR->Read(".ldap.error");
                y2error("Can not add syncaccount entry.");
                y2error( $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
                if ( $ldapERR->{'code'} != 68 ) # already exists */
                {
                    return 0;
                }
            }
            y2milestone("sync entries added");
        }
        else
        {
            y2milestone("Authentication information for database ".$syncreplaccount->{'basendn'} ." unavailable");
        }
    }
    return 1;
}

sub CreatePpolicyObjects
{
    my $self = shift; 
    foreach my $suffix ( keys( %$ppolicy_objects ) )
    {
        my $ppolicy = $ppolicy_objects->{$suffix};
        if ( ! defined $ppolicy )
        {
            y2milestone("No default policy for for database $suffix");
            return undef;
        }
        if ( ! defined $ppolicy->{'dn'} || ! defined $ppolicy->{'ppolicy'} )
        {
            y2milestone("No default policy for for database $suffix");
            return undef;
        }
        my $ldapERR;
        my $db_auth = $self->ReadAuthInfo( $suffix );
        if ( ! defined $db_auth )
        {
            y2error("AuthInfo for database $suffix unavailable");
            return undef;
        }
        if (! SCR->Execute(".ldap.bind", {"bind_dn" => $db_auth->{'bind_dn'},
                                          "bind_pw" => $db_auth->{'bind_pw'}}) ) {
            $ldapERR = SCR->Read(".ldap.error");
            y2error( "LDAP bind failed" );
            y2error( $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
            return undef;
        }
        my $entries = SCR->Read (".ldap.search",  { "base_dn" =>  $ppolicy->{'dn'},
                                                 "filter"  => "objectclass=*",
                                                 "scope"   => 0 } );
        my $path = ".ldap.add";
        if ( defined $entries && scalar(@{$entries}) > 0 )
        {
            $path = ".ldap.modify"
        }
        if (! SCR->Write($path, { dn => $ppolicy->{'dn'}, 'check_attrs' => 1 } ,
                                        $ppolicy->{'ppolicy'} ))
        {
            $ldapERR = SCR->Read(".ldap.error");
            y2error("Can not add ppolicy entry.");
            y2error( $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
        }
        y2milestone("Ppolicy entry added");
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
    elsif ( ! $serviceRunning && $serviceEnabled )
    {
        my $progressItems = [_("Starting LDAP Server") ];
        Progress->New(_("Restarting OpenLDAP Server"), "", 1, $progressItems, $progressItems, "");
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
        if ( ! $self->ReadServiceEnabled() )
        {
            return 1;
        }
        $overwriteConfig = 0;
        my $progressItems = [ _("Writing Startup Configuration"),
                _("Cleaning up config directory"),
                _("Creating Configuration"),
                _("Starting OpenLDAP Server"),
                _("Creating Base Objects") ];
        Progress->New(_("Writing OpenLDAP Server Configuration"), "", 5, $progressItems, $progressItems, "");

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
            $self->SetError( _("Enabling the LDAPI Protocol listener failed.") );
            Progress->Finish();
            return 0;
        }
        if ( $registerSlp == 1 || 
               ( ref($registerSlp) eq "YaST::YCP::Boolean" && $registerSlp->value == 1 ) 
           )
        {
            SCR->Write('.sysconfig.openldap.OPENLDAP_REGISTER_SLP', 'yes');
        }
        else
        {
            SCR->Write('.sysconfig.openldap.OPENLDAP_REGISTER_SLP', 'no');
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
            my $ldif = "";
            if ( $setupSyncreplSlave )
            {
                $ldif = $masterldif;
            }
            else
            {
                $ldif = SCR->Read('.ldapserver.configAsLdif');
            }
            y2debug($ldif);
            if ( ! $ldif )
            {
                my $err = SCR->Error(".ldapserver");
                y2error("Creating LDIF for initial configuration failed");
                $self->SetError( $err->{'summary'}, $err->{'description'} );
                # cleanup
                SCR->Execute('.target.bash', "rm -f $tmpfile" );
                return 0;
            }
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
        if ( $write_ldapconf )
        {
            y2milestone("Updating /etc/openldap/ldap.conf");
            SCR->Write(".etc.ldap_conf.value.\"/etc/openldap/ldap.conf\".host",
		["localhost"]);
	    SCR->Write(".etc.ldap_conf.value.\"/etc/openldap/ldap.conf\".base",
		[$ldapconf_base]);
            my $tls = $self->ReadTlsConfig();
            if ( ref($tls) eq "HASH" && $tls->{'caCertFile'} ne "" )
            {
	        SCR->Write(".etc.ldap_conf.value.\"/etc/openldap/ldap.conf\".tls_cacert",
		    [$tls->{'caCertFile'}]);
            }
            SCR->Write(".etc.ldap_conf", "force" );
        }
        $self->CreateBaseObjects();
        if ( $setupSyncreplMaster )
        {
            $self->CreateSyncReplAccount();
        }
        if (! $usesBackConfig )
        {
            SCR->Execute('.target.bash', 'cp -f /etc/openldap/slapd.conf /etc/openldap/slapd.conf.YaSTsave' );
            SCR->Write(".target.string",
                       "/etc/openldap/slapd.conf",
                    "#\n".
                    "# Note: The OpenLDAP configuration has been created by YaST. YaST does not\n".
                    "#       use /etc/openldap/slapd.conf to store the OpenLDAP configuration anymore.\n".
                    "#       YaST uses OpenLDAP\'s dynamic configuration database (back-config) to\n".
                    "#       store the LDAP server\'s configuration.\n".
                    "#       For details about the dynamic configuration backend please see the\n".
                    "#       slapd-config(5) manpage or the OpenLDAP Software 2.4 Administrator's Guide\n".
                    "#       located at /usr/share/doc/packages/openldap2/guide/admin/guide.html\n".
                    "#       on this system.\n".
                    "#\n".
                    "#       A copy of the original /etc/openldap/slapd.conf file has been created as:\n".
                    "#           /etc/openldap/slapd.conf.YaSTsave\n".
                    "#\n".
                    "#       To access the new configuration backend easily you can use SASL external\n".
                    "#       authentication. I.e. the following ldapsearch command, executed as the root\n".
                    "#       user, can be used to print the complete slapd configuration to stdout:\n".
                    "#          ldapsearch -Y external -H ldapi:/// -b cn=config\n".
                    "#\n"
                );
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
            Progress->New(_("De-activating OpenLDAP Server"), "", 2, $progressItems, $progressItems, "");
            Progress->NextStage();
            Service->Disable("ldap");
            Progress->NextStage();
            Service->Stop("ldap");
            Progress->Finish();
            return 1;
        }
        if ( ! $wasEnabled && $serviceEnabled )
        {
            Service->Enable("ldap");
            Service->Start("ldap");
        }
        my $progressItems = [ _("Writing Sysconfig files"),
                              _("Applying changes to Configuration Database"),
                              _("Applying changes to /etc/openldap/ldap.conf"),
                              _("Creating Base Objects for newly created databases"),
                              _("Updating Default Password Policy Objects"),
                              _("Waiting for OpenLDAP background indexing tasks to complete (this might take some minutes)"),
                              _("Restarting OpenLDAP Server if required"),
                            ];

        Progress->New(_("Writing OpenLDAP Configuration"), "", 7, $progressItems, $progressItems, "");
        Progress->NextStage();

        # these changes require a restart of slapd
        if ( $use_ldap_listener )
        {
            if (SCR->Read('.sysconfig.openldap.OPENLDAP_START_LDAP') eq "no" )
            {
                SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAP', 'yes');
                $restartRequired = 1;
            }
        } 
        else
        {
            if (SCR->Read('.sysconfig.openldap.OPENLDAP_START_LDAP') eq "yes" )
            {
                SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAP', 'no');
                $restartRequired = 1;
            }
        }
        if ( $use_ldapi_listener )
        {
            if (SCR->Read('.sysconfig.openldap.OPENLDAP_START_LDAPI') eq "no" )
            {
                SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPI', 'yes');
                $restartRequired = 1;
            }
        } 
        else
        {
            if (SCR->Read('.sysconfig.openldap.OPENLDAP_START_LDAPI') eq "yes" )
            {
                SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPI', 'no');
                $restartRequired = 1;
            }
        }
        if ( $use_ldaps_listener )
        {
            if (SCR->Read('.sysconfig.openldap.OPENLDAP_START_LDAPS') eq "no" )
            {
                SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPS', 'yes');
                $restartRequired = 1;
            }
        } 
        else
        {
            if (SCR->Read('.sysconfig.openldap.OPENLDAP_START_LDAPS') eq "yes" )
            {
                SCR->Write('.sysconfig.openldap.OPENLDAP_START_LDAPS', 'no');
                $restartRequired = 1;
            }
        }
        if ( $registerSlp == 1 || 
               ( ref($registerSlp) eq "YaST::YCP::Boolean" && $registerSlp->value == 1 ) 
           )
        {
            if (SCR->Read('.sysconfig.openldap.OPENLDAP_REGISTER_SLP') eq "no" )
            {
                SCR->Write('.sysconfig.openldap.OPENLDAP_REGISTER_SLP', 'yes');
                $restartRequired = 1;
            }
        }
        else
        {
            if (SCR->Read('.sysconfig.openldap.OPENLDAP_REGISTER_SLP') eq "yes" )
            {
                SCR->Write('.sysconfig.openldap.OPENLDAP_REGISTER_SLP', 'no');
                $restartRequired = 1;
            }
        }
        # FIXME:
        # Explicit cache flush, see bnc#350581 for details
        SCR->Write(".sysconfig.openldap", undef);
        my $progress_orig = Progress->set(0);
        SuSEFirewall->Write();
        Progress->set($progress_orig);
        Progress->NextStage();

        if( ! SCR->Execute('.ldapserver.commitChanges' ) )
        {
            my $err = SCR->Error(".ldapserver");
            y2error($err->{'summary'}." ".$err->{'description'});
            $self->SetError( $err->{'summary'}, $err->{'description'} );
            return 0;
        }
        Progress->NextStage();
        if ( $write_ldapconf )
        {
            SCR->Write(".etc.ldap_conf.value.\"/etc/openldap/ldap.conf\".host",
		["localhost"]);
	    SCR->Write(".etc.ldap_conf.value.\"/etc/openldap/ldap.conf\".base",
		[$ldapconf_base]);
            y2milestone("Updated /etc/openldap/ldap.conf");
        }
        Progress->NextStage();
        if ( ! $self->CreateBaseObjects() )
        {
            y2error("Error while creating base objects");
            $self->SetError( _("Creating base objects failed.") );
            Progress->Finish();
            return 0;
        }
        Progress->NextStage();
        if ( ! $self->CreatePpolicyObjects() )
        {
            y2error("Error while creating Password Policy objects");
            $self->SetError( _("Creating Password Policy objects failed.") );
            Progress->Finish();
            return 0;
        }

        if ( $restartRequired )
        {
            # An indexing Task might be running, wait for it to complete
            # before restarting the server (bnc#450457)
            Progress->NextStage();
            y2milestone("slapd might be running a background task, waiting for completion");
            SCR->Execute('.ldapserver.waitForBackgroundTasks') ;
            y2milestone("background tasks completed");
            Progress->NextStage();
            Service->Restart("ldap");
        }
        else
        {
            Progress->NextStage();
            Progress->NextStage();
        }
        Progress->Finish();
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
    y2debug("LdapServer::Import() : ". Data::Dumper->Dump([$hash]));

    if ( (! keys( %$hash ))  || (! defined $hash->{'daemon'}) || 
         (! defined $hash->{'globals'}) || (! defined $hash->{'databases'}) )
    {
        $usingDefaults = 1;
        $overwriteConfig = 0;
        $self->WriteServiceEnabled( 0 );
        y2milestone("Wrong/empty ldap-server profile");
        return 0;
    }

    if ( defined $hash->{'daemon'}->{'serviceEnabled'} )
    {
        $self->WriteServiceEnabled( $hash->{'daemon'}->{'serviceEnabled'} );
    }
    else
    {
        $self->WriteServiceEnabled(0);
    }

    if ( ! $self->ReadServiceEnabled() )
    {
        return 1;
    }

    $usingDefaults = 0;
    $overwriteConfig = 1;

    if ( defined $hash->{'daemon'}->{'slp'} )
    {
        $self->WriteSLPEnabled( $hash->{'daemon'}->{'slp'} );
    }
    else
    {
        $self->WriteSLPEnabled( 0 );
    }

    foreach my $listner (@{$hash->{'daemon'}->{'listners'} } )
    {
        $self->WriteProtocolListenerEnabled($listner, 1);
    }

    SCR->Execute('.ldapserver.initGlobals' );
    if ( defined $hash->{'globals'}->{'loglevel'} )
    {
        $self->WriteLogLevels( $hash->{'globals'}->{'loglevel'} );
    }
    if ( defined  $hash->{'globals'}->{'allow'} )
    {
        $self->WriteAllowFeatures( $hash->{'globals'}->{'allow'} );
    }
    if ( defined $hash->{'globals'}->{'disallow'} )
    {
        $self->WriteDisallowFeatures( $hash->{'globals'}->{'disallow'} );
    }
    if ( defined  $hash->{'globals'}->{'tlsconfig'} )
    {
        $self->WriteTlsConfig( $hash->{'globals'}->{'tlsconfig'} = $self->ReadTlsConfig() );
    }

    SCR->Execute('.ldapserver.initSchema' );
    foreach my $schema (@{$hash->{'schema'}})
    {
        if ( defined $schema->{'includeldif'} )
        {
            $self->AddLdifToSchemaList($schema->{'includeldif'});
        }
        elsif ( defined $schema->{'includeschema'} )
        {
            $self->AddSchemaToSchemaList($schema->{'includeschema'});
        }
        else # Import ldif string
        {

        }
    }
    my $cfgdatabase = { 'type' => 'config',
                        'rootdn' => 'cn=config' };
    my $frontenddb = { 'type' => 'frontend' };
    SCR->Execute('.ldapserver.initDatabases', [ $frontenddb, $cfgdatabase ] );
    SCR->Write(".ldapserver.database.{-1}.acl", $defaultGlobalAcls );
    my $i = 1;
    my $defIdxBak = $defaultIndexes;
    $defaultIndexes = [];
    my $defAclBak = $defaultDbAcls;
    $defaultDbAcls = [];
    foreach my $database (@{$hash->{'databases'}})
    {
        $self->AddDatabase($i, $database, 1);
        foreach my $idx ( keys %{$database->{'indexes'}} )
        {
            my $idxHash = {
                "name" => $idx,
                "eq" =>  $database->{'indexes'}->{$idx}->{'eq'} || 0,
                "sub" =>  $database->{'indexes'}->{$idx}->{'sub'} || 0,
                "pres" =>  $database->{'indexes'}->{$idx}->{'pres'} || 0,
            };
            $self->ChangeDatabaseIndex( $i, $idxHash );
        }
        if ( defined $database->{'access'} )
        {
            $self->ChangeDatabaseAcl( $i, $database->{'access'} );
        }
    }
    $defaultIndexes = $defIdxBak;
    $defaultDbAcls = $defAclBak;

    my $ldif = SCR->Read('.ldapserver.configAsLdif' );
    y2debug($ldif);
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
    if ( ! $self->ReadServiceEnabled() )
    {
        return $hash;
    }

    $hash->{'daemon'}->{'slp'} = $self->ReadSLPEnabled(); 
    $hash->{'daemon'}->{'serviceEnabled'} = $self->ReadServiceEnabled(); 

    my @listeners = ();
    if ( $self->ReadProtocolListenerEnabled("ldap") )
    {
        push @listeners, "ldap";
    }
    if ( $self->ReadProtocolListenerEnabled("ldapi") )
    {
        push @listeners, "ldapi";
    }
    if ( $self->ReadProtocolListenerEnabled("ldaps") )
    {
        push @listeners, "ldaps";
    }
    $hash->{'daemon'}->{'listeners'} = \@listeners;

    my @schema = ();
    my $schemaList = $self->ReadSchemaList();

    foreach my $schema (@$schemaList)
    {
        my $schemaDef = {};
        # Don't include definitions of well know Schema shipping with the
        # openldap2 RPMs
        if ( $schema eq "core" || $schema eq "cosine" || $schema eq "inetorgperson" ||
             $schema eq "nis" )
        {
            $schemaDef->{'includeldif'} = "/etc/openldap/schema/".$schema.".ldif";
        }
        elsif ( $schema eq "dnszone" || $schema eq "ppolicy" || $schema eq "rfc2307bis" ||
                $schema eq "suse-mailserver" || $schema eq "yast" )
        {
            $schemaDef->{'includeschema'} = "/etc/openldap/schema/".$schema.".schema";
        }
        else
        {
            $schemaDef->{'name'} = $schema;
            $schemaDef->{'definition'} = SCR->Read(".ldapserver.schema.ldif.$schema");
        }
        push @schema, $schemaDef;
    }
    $hash->{'schema'} = \@schema;
    $hash->{'globals'}->{'loglevel'} = $self->ReadLogLevels();
    $hash->{'globals'}->{'allow'} = $self->ReadAllowFeatures();
    $hash->{'globals'}->{'disallow'} = $self->ReadDisallowFeatures();
    $hash->{'globals'}->{'tlsconfig'} = $self->ReadTlsConfig();

    my $dbList = $self->ReadDatabaseList();
    my @dbs;
    foreach my $db (@$dbList)
    {
        if ( $db->{'type'} eq "config" || $db->{'type'} eq "frontend" )
        {
            next;
        }
        my $dbhash = $self->ReadDatabase($db->{'index'} );
        $dbhash->{'access'} = $self->ReadDatabaseAcl( $db->{'index'} );
        $dbhash->{'indexes'} = $self->ReadDatabaseIndexes( $db->{'index'} );
        push @dbs, $dbhash;
    }
    $hash->{'databases'} = \@dbs;

    y2debug("LdapServer::Export() ". Data::Dumper->Dump([$hash]));
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
    my $string;
    if ( keys(%dbDefaults) && ! $readConfig )
    {
        $string .= '<h2>'._("Startup Configuration").'</h2>'
                .'<p>'._("Start LDAP Server: ").'<code>'.($dbDefaults{'serviceEnabled'}->value?_("Yes"):_("No")).'</code></p>'
                .'<p>'._("Register at SLP Service: ").'<code>'.($dbDefaults{'slpRegister'}->value?_("Yes"):_("No")).'</code></p>';

        if ( $dbDefaults{'serviceEnabled'}->value )
        {
            $string .= '<h2>'._("Create initial Database with the following Parameters").'</h2>'
                .'<p>'._("Database Suffix: ").'<code>'.$dbDefaults{'suffix'}.'</code></p>'
                .'<p>'._("Administrator DN: ").'<code>'.$dbDefaults{'rootdn'}.'</code></p>';
        }
    }
    elsif ( ! $usingDefaults )
    {
        my $dbList = $self->ReadDatabaseList();
        $string .= '<h2>'._("Startup Configuration").'</h2>'
                .'<p>'._("Start LDAP Server: ").'<code>'.($serviceEnabled?_("Yes"):_("No")).'</code></p>'
                .'<p>'._("Register at SLP Service: ").'<code>'.($registerSlp?_("Yes"):_("No")).'</code></p>'
                .'<h2>'._("Create the following databases:").'</h2>';
        foreach my $db ( @$dbList )
        {
            if ($db->{'type'} ne "frontend" && $db->{'type'} ne "config" )
            {
                $string .= '<p>'._("Database Suffix: ").'<code>'.$db->{'suffix'}.'</code><br>'
                    ._("Database Type: ").'<code>'.$db->{'type'}.'</code></p>';
            }
        }
    }
    else
    {
        $string .= _("Not configured yet.");    
    }

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
	"install" => ( "openldap2", "openldap2-client" ),
	"remove" => (),
    );
    return \%ret;
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
    my $value = shift;
    y2milestone("WriteSlpEnabled");
    if ( $value == 1 || $value == 0 ) # convert to YaST::YCP::Boolean
    {
        $registerSlp = YaST::YCP::Boolean($value);
    }
    else  #most probably already a YaST::YCP::Boolean
    {
        $registerSlp = $value;
    }
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

BEGIN { $TYPEINFO {ReadServerIds} = ["function", [ "list", [ "map", "string", "any"  ] ] ]; }
sub ReadServerIds
{
    my $self = shift;

    my $serverids = SCR->Read( '.ldapserver.global.serverIds' );
    foreach my $sid ( @{$serverids} )
    {
        $sid->{'id'} = YaST::YCP::Integer( $sid->{'id'} );
    }
    return $serverids;
}

BEGIN { $TYPEINFO {WriteServerIds} = ["function", "boolean", [ "list", [ "map", "string", "any"  ] ] ]; }
sub WriteServerIds
{
    my ( $self, $serverids ) = @_;
    y2milestone( "WriteServerIds" );
    foreach my $sid ( @{$serverids} )
    {
        $sid->{'id'} = YaST::YCP::Integer( $sid->{'id'} );
    }
    my $ret = SCR->Write( '.ldapserver.global.serverIds', $serverids );
    return $ret;
}

BEGIN { $TYPEINFO {AssignServerId} = ["function", "boolean" ]; }
sub AssignServerId
{
    my ( $self, $fqdn ) = @_;
    if ( ! $fqdn )
    {
        $fqdn = $self->ReadHostnameFQ();
    }
    if ( $fqdn eq "" )
    {
        y2error("Unable to determine full-qualified hostname");
        return 0;
    }

    SCR->Execute('.ldapserver.assignServerId', "ldap://".$fqdn );
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
    my $oldtls = $self->ReadTlsConfig();
    if ( ref($oldtls) eq "HASH" )
    {
        if( $oldtls->{'certKeyFile'} ne $tls->{'certKeyFile'} ||
            $oldtls->{'certFile'} ne $tls->{'certFile'} ||
            $oldtls->{'caCertFile'} ne $tls->{'caCertFile'} )
        {
            $restartRequired = 1;
        }
    }
    elsif ( $tls->{'tls_active'} )
    {
        $restartRequired = 1;
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
    Progress->New(_("Migrating LDAP Server Configuration"), "", 3, $progressItems, $progressItems, "");
    
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

##
 # Read the settings used for creating the initial server setup. If those
 # settings do not exist currently. A call to this function will create a
 # proposal with useful default (by calling LdapServer::InitDbDefaults() )
 # 
 # @return A Map containing the setting to use when creating the initial setup
 #
BEGIN { $TYPEINFO {CreateInitialDefaults} = ["function", [ "map", "string", "any"] ]; }
sub CreateInitialDefaults
{
    y2milestone("CreateInitialDefaults");
    my $self = shift;
    if ( ! keys(%dbDefaults ) ) {
        $self->InitDbDefaults();
        $usingDefaults = 1;
    }
    y2debug(Data::Dumper->Dump([\%dbDefaults]));
    $overwriteConfig = 1;
    return \%dbDefaults;
}

BEGIN { $TYPEINFO {SetInitialDefaults} = ["function", "boolean", [ "map", "string", "any" ] ]; }
sub SetInitialDefaults
{
    my $self = shift;
    my $defaults = shift;
    $self->WriteServiceEnabled( $defaults->{'serviceEnabled'} );
    if ( defined $defaults->{'serviceEnabled'} )
    {
        $defaults->{'serviceEnabled'} =  YaST::YCP::Boolean($defaults->{'serviceEnabled'});
    }
    else
    {
        $defaults->{'serviceEnabled'} =  $dbDefaults{'serviceEnabled'};
    }
    if ( defined $defaults->{'slpRegister'} )
    {
        $defaults->{'slpRegister'} =  YaST::YCP::Boolean($defaults->{'slpRegister'});
    }
    else
    {
        $defaults->{'slpRegister'} =  $dbDefaults{'slpRegister'};
    }
    y2debug("SetInitialDefaults: ". Data::Dumper->Dump([$defaults]));
    %dbDefaults = %$defaults;
    $usingDefaults = 0;
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
        $domain = Hostname::CurrentDomain();
        if ( $domain eq "" )
        {
            y2milestone("unable to determine domainname falling back to hard-coded default");
            $domain = "site";
        }
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
    $dbDefaults{'type'} = "hdb";
    $dbDefaults{'suffix'} = $basedn;
    $dbDefaults{'directory'} = "/var/lib/ldap";
    $dbDefaults{'rootdn'} = "cn=Administrator,".$basedn;
    $dbDefaults{'rootpw'} = "";
    $dbDefaults{'rootpw_clear'} = "";
    $dbDefaults{'pwenctype'} = "SSHA";
    $dbDefaults{'entrycache'} = 10000;
    $dbDefaults{'idlcache'} = 30000;
    $dbDefaults{'checkpoint'} = [ 1024, 5 ];
    $dbDefaults{'defaultIndex'} = YaST::YCP::Boolean(1);
    $dbDefaults{'serviceEnabled'} = YaST::YCP::Boolean(1);
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
    y2milestone( "ReadFromDefaults" );
    $self->WriteServiceEnabled( $dbDefaults{'serviceEnabled'} );
    $self->WriteSLPEnabled( $dbDefaults{'slpRegister'} );
    my $pwHash = "";
    if ( $dbDefaults{'pwenctype'} && $dbDefaults{'rootpw_clear'} ) {
        $pwHash = $self->HashPassword($dbDefaults{'pwenctype'}, $dbDefaults{'rootpw_clear'} );
    }
    my $database = { 'type' => $dbDefaults{'type'},
                     'suffix' => $dbDefaults{'suffix'},
                     'rootdn' => $dbDefaults{'rootdn'},
                     'rootpw' => $pwHash,
                     'directory' => $dbDefaults{'directory'},
                     'entrycache' => YaST::YCP::Integer($dbDefaults{'entrycache'}),
                     'idlcache' => YaST::YCP::Integer($dbDefaults{'idlcache'}),
                     'checkpoint' => [ YaST::YCP::Integer($dbDefaults{'checkpoint'}->[0]),
                                       YaST::YCP::Integer($dbDefaults{'checkpoint'}->[1]) ]
                    };

    my $cfgdatabase = { 'type' => 'config',
                        'rootdn' => 'cn=config' };
    my $frontenddb = { 'type' => 'frontend' };

    $self->InitGlobals();

    if (! $self->ReadSetupSlave() ) # Slave setup was already initialized by dumping Master
                                    # Database to $masterldif, nothing to do here.
    {
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
        $rc = SCR->Write(".ldapserver.schema.addFromSchemafile", "/etc/openldap/schema/yast.schema" );
        if ( ! $rc ) {
            my $err = SCR->Error(".ldapserver");
            y2error("Adding Schema failed: ".$err->{'summary'}." ".$err->{'description'});
            $self->SetError( $err->{'summary'}, $err->{'description'} );
            return $rc;
        }

        if ( ! defined SCR->Read(".target.dir", $database->{directory}) ) {
            my $ret = SCR->Execute(".target.bash", "mkdir -m 0700 -p ".$database->{directory});
            if( ( $ret ) && ( ! defined  SCR->Read(".target.dir", $database->{directory}) ) ) {
                $self->SetError(_("Could not create database directory."), "");
                return $ret;
            }
            my $owner = SCR->Read('.sysconfig.openldap.OPENLDAP_USER');
            my $group = SCR->Read('.sysconfig.openldap.OPENLDAP_GROUP');
            $ret = SCR->Execute(".target.bash", "chown ".$owner.":".$group." ".$database->{directory});
            if ( $ret ) {
                $self->SetError(_("Could adjust ownership of database directory."), "");
                return $ret;
            }
        }
        SCR->Execute('.ldapserver.initDatabases', [ $frontenddb, $cfgdatabase, $database ] );
        if ( $dbDefaults{'defaultIndex'} == 1 || 
             ( ref($dbDefaults{'defaultIndex'}) eq "YaST::YCP::Boolean" &&
               $dbDefaults{'defaultIndex'}->value == 1 ) 
           )
        {
            foreach my $idx ( @$defaultIndexes )
            {
                $self->ChangeDatabaseIndex(1, $idx );
            }
        }
        $self->WriteLdapConfBase($database->{'suffix'});

        if ( defined $dbDefaults{'configpw'} && $dbDefaults{'configpw'} ne "" )
        {
            my $confPwHash =  $self->HashPassword($dbDefaults{'pwenctype'}, $dbDefaults{'configpw'} );
            my $changes = { "secure_only" => 1, "rootpw" => $confPwHash };
            $self->UpdateDatabase(0 ,$changes);
            if ( $self->ReadSetupMaster() )
            {
                if ( $self->ReadSetupMirrorMode() )
                {
                    $self->AssignServerId();
                }
                # create helpful indexes for syncrepl
                $self->ChangeDatabaseIndex(1, { "name" => "entryUUID", "eq" => 1 } );
                $self->ChangeDatabaseIndex(1, { "name" => "entryCSN", "eq" => 1 } );

                my $syncprov = { 'enabled' => 1, 
                                 'checkpoint' => { 'ops' => YaST::YCP::Integer(100),
                                                   'min' => YaST::YCP::Integer(10) }
                                };

                SCR->Write( ".ldapserver.database.{0}.syncprov", $syncprov );
                SCR->Write( ".ldapserver.database.{1}.syncprov", $syncprov );

                my $syncpw = GenerateRandPassword();
                my $syncdn = "uid=syncrepl,ou=system,".$dbDefaults{'suffix'};
                my $hostname = $self->ReadHostnameFQ();
                if ( $hostname eq "" )
                {
                    $self->SetError( _("Could not determine own full qualified hostname"), 
                         _("A master server for replication cannot work correctly without knowing the own full qualified hostname") );
                    return 0;
                }
                my $syncrepl = {
                        "provider" => {
                                "protocol"  => "ldap",
                                "target"    => $hostname,
                                "port"      => YaST::YCP::Integer(389)
                            },
                        "type" => "refreshAndPersist",
                        "binddn" => $syncdn,
                        "credentials" => $syncpw,
                        "basedn" => "cn=config",
                        "starttls" => YaST::YCP::Boolean(1),
                        "syncrepl" => { 'use_provider' => YaST::YCP::Boolean(1) }
                    };
                SCR->Write(".ldapserver.database.{0}.syncrepl", $syncrepl );
                $syncrepl->{'basedn'} = $dbDefaults{'suffix'};
                SCR->Write(".ldapserver.database.{1}.syncrepl", $syncrepl );
                $syncreplaccount->{'syncdn'} = $syncdn;
                $syncreplaccount->{'syncpw'} = $syncpw;
                $syncreplaccount->{'syncpw_hash'} = $self->HashPassword($dbDefaults{'pwenctype'}, $syncpw );
                $syncreplaccount->{'basedn'} = $dbDefaults{'suffix'};
                my @syncacl = ({
                        'target' => {},
                        'access' => [
                                { 'type' => "dn.base",
                                  'value' => $syncdn,
                                  'level' => "read",
                                  'control' => "" },
                                { 'type' => "*",
                                  'value' => "",
                                  'level' => "",
                                  'control' => "break" }
                            ]
                    });
                $rc = SCR->Write(".ldapserver.database.{0}.acl", \@syncacl );
                push @syncacl, @$defaultDbAcls;
                $defaultDbAcls = \@syncacl;

                my @newlimits = ( { 'selector' => "dn.exact=\"$syncdn\"",
                                    'limits'   => [ { 'type'  => "size.soft",
                                                      'value' => "unlimited" } ] } );
                SCR->Write(".ldapserver.database.{0}.limits", \@newlimits );
                SCR->Write(".ldapserver.database.{1}.limits", \@newlimits );
            }
        }
        
        # add default ACLs
        $rc = SCR->Write(".ldapserver.database.{-1}.acl", $defaultGlobalAcls );
        $rc = SCR->Write(".ldapserver.database.{1}.acl", $defaultDbAcls );
        push @added_databases, $dbDefaults{'suffix'};
        $self->WriteAuthInfo( $dbDefaults{'suffix'}, 
                            { bind_dn => $dbDefaults{'rootdn'},
                              bind_pw => $dbDefaults{'rootpw_clear'} } );
    }
    $usingDefaults = 0;
    $readConfig = 1;
    return 1;
}

##
 # Read the list of configured Databases.
 #
 # @return A list of hashes. Each hash represents a database and has the keys
 #         'type' (e.g. "hdb" or "bdb"), 'suffix' (the base DN of the database) and
 #         'index' (the index number used by back-config to order databases correctly)
 #
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

BEGIN { $TYPEINFO {ReadDatabase} = ["function", [ "map" , "string", "any"], "integer" ]; }
sub ReadDatabase
{
    my ($self, $index) = @_;
    y2milestone("ReadDatabase ".$index);
    my $rc = SCR->Read(".ldapserver.database.{".$index."}" );
    if ( defined $rc->{'secure_only'} )
    {
        $rc->{'secure_only'} = YaST::YCP::Boolean($rc->{'secure_only'}); 
    }
    y2debug( "Database: ".Data::Dumper->Dump([$rc]) );
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
    y2debug("ChangeDatabaseIndex: ".Data::Dumper->Dump([$newIdx]) );
    if( defined $newIdx->{'pres'} )
    {
        $newIdx->{'pres'} = YaST::YCP::Boolean($newIdx->{'pres'});
    }
    if( defined $newIdx->{'eq'} )
    { 
        $newIdx->{'eq'} = YaST::YCP::Boolean($newIdx->{'eq'});
    }
    if( defined $newIdx->{'sub'} )
    { 
        $newIdx->{'sub'} = YaST::YCP::Boolean($newIdx->{'sub'});
    }
    my $rc = SCR->Write(".ldapserver.database.{".$dbIndex."}.index", $newIdx );
    return $rc;
}

##
 # Update the ACLs of a Database, all exiting ACLs of that Database are overwritten.
 #
 # @param The index of the Database to be updated
 # @param A list of maps defining the new ACLs. The maps must 
 #        adhere to the following structure:
 #          {
 #              'target' => {
 #                      # a Map defining the target objects of this ACL
 #                      # can contain any or multiple keys of the following
 #                      # types
 #                      'attrs'  => <A comma-separated string of attributetypes>,
 #                      'filter' => <LDAP filter string>,
 #                      'dn' => {
 #                              'style' => <'base' or 'subtree'>
 #                              'value' => <LDAP DN>
 #                          }
 #                  },
 #              'access' => [
 #                      # a list of maps defining the access level of different
 #                      # indentities, each map looks like this:
 #                      'level' => <'none'|'disclose'|'auth'|'compare'|'read'|'write'|'manage'>,
 #                      'type'  => <'self'|'users'|'anoymous'|'*'|'group'|'dn.base'|'dn.subtree'>
 #                      # if type is 'group', 'dn.base', 'dn.subtree':
 #                      'value'    => <a valid LDAP DN>
 #                      'control'  => <'stop'|'break'|'continue'>                      '
 #                  ]
 #
 #          }
 # @return boolean True on success
 #
BEGIN { $TYPEINFO {ChangeDatabaseAcl} = ["function", "boolean" , "integer", ["list", [ "map", "string", "any" ] ] ]; }
sub ChangeDatabaseAcl
{
    my ($self, $dbIndex, $acllist ) = @_;
    y2debug("ChangeDatabaseAcl: ".Data::Dumper->Dump([$acllist]) );

    # Check whether this is a slave database, if yes locate the 
    # syncrepl related ACL and move it to the top. This is to ensure
    # that syncrepl clients have read access to everything
    my $syncrepl = $self->ReadSyncRepl( $dbIndex );
    if ( @$syncrepl > 0 && scalar(keys %{$syncrepl->[0]}) && $syncrepl->[0]->{'binddn'} ne "" )
    {
        my $binddn =  $syncrepl->[0]->{'binddn'};
        my $acllist_sorted=[];
        my $syncacl={};
        my $found=0;

        foreach my $rule ( @{$acllist} )
        {
            if ( !$found && (keys %{$rule->{'target'}} == 0) )
            {
                # this rule matches all db entries, check if it gives
                # read access to the syncrepl id
                foreach my $access ( @{$rule->{'access'}} )
                {
                    if ( $access->{'type'} eq "dn.base" && 
                         lc($access->{'value'}) eq lc( $binddn ) &&
                         ($access->{'level'} eq "read" || $access->{'level'} eq "write")
                       )
                    {
                        y2milestone("Found syncrepl ACL, moving to first position");
                        $syncacl=$rule;
                        $found=1;
                        last;
                    }
                }
                if( $found )
                {
                    next;
                }
            }
            push @{$acllist_sorted}, $rule;
        }
        if ( $found ) 
        {
            # push syncrepl acl on top
            push @{$acllist_sorted}, $syncacl;
            $acllist = [ $syncacl ];
            push @{$acllist}, @{$acllist_sorted};
        }
    }



    my $rc = SCR->Write(".ldapserver.database.{".$dbIndex."}.acl", $acllist );
    if ( ! $rc )
    {
        my $err = SCR->Error(".ldapserver");
        $self->SetError( $err->{'summary'}, $err->{'description'} );
    }
    return $rc;
}

##
 # Read the ACLs of a Database
 # @param The index of the Database to be read
 #
 # @return A list of maps as described for the ChangeDatabaseAcl() function
 #
BEGIN { $TYPEINFO {ReadDatabaseAcl} = ["function", [ "list", [ "map", "string", "any" ] ], "integer" ]; }
sub ReadDatabaseAcl
{
    my ($self, $index) = @_;
    y2milestone("ReadDatabaseAcl ".$index);
    my $rc = SCR->Read(".ldapserver.database.{".$index."}.acl" );
    y2debug( "ACL: ".Data::Dumper->Dump([$rc]) );
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

    if ( ! SCR->Write(".ldapserver.database.{".$dbIndex."}.ppolicy", $ppolicy ) )
    {
        my $err = SCR->Error(".ldapserver");
        $self->SetError( $err->{'summary'}, $err->{'description'} );
        return YaST::YCP::Boolean(0);
    }
    elsif  ( 0 < scalar(keys %{$ppolicy}) )
    {
        # add ACL to protect password policy related Attributes
        my $acl = $self->ReadDatabaseAcl( $dbIndex );
        my @ppAttrs = ( "pwdChangedTime", "pwdAccountLockedTime",
                        "pwdFailureTime", "pwdHistory",
                        "pwdGraceUseTime", "pwdReset" );
        # check if ACLs for ppolicy Attribute are already present
        foreach my $aclItem (@$acl)
        {
            if ( defined $aclItem->{'target'} && defined $aclItem->{'target'}->{'attrs'} )
            {
                my @attrs = split /,/, $aclItem->{'target'}->{'attrs'};
                foreach my $attr (@attrs)
                {
                    @ppAttrs = grep(!/^$attr$/, @ppAttrs );
                }
            }
        }
        if ( scalar(@ppAttrs) > 0 )
        {
            my $dbList = $self->ReadDatabaseList();
            my $suffix = "";
            foreach my $db (@$dbList) 
            {
                if ($db->{'index'} == $dbIndex )
                {
                    $suffix = $db->{'suffix'};
                    last;
                }
            }
            my $attrString =  join ",", @ppAttrs;
            my @ppAcl = ( { 'target' => { 'attrs' => $attrString },
                            'access' => [ { 'level' => 'none',
                                            'type'  => '*' } ] } );
            push @ppAcl, (@$acl );
            $self->ChangeDatabaseAcl( $dbIndex, \@ppAcl );
        }
    }
    return YaST::YCP::Boolean(1);
}

BEGIN { $TYPEINFO {ReadSyncProv} = ["function", [ "map" , "string", "any" ], "integer" ]; }
sub ReadSyncProv
{
    my ($self, $index) = @_;
    y2milestone("ReadSyncProv ", $index);
    my $syncprov = SCR->Read(".ldapserver.database.{".$index."}.syncprov" );
    y2debug( "Syncprov: ".Data::Dumper->Dump([$syncprov]) );
    if (defined $syncprov->{'checkpoint'} )
    {
        $syncprov->{'checkpoint'} = {
            "ops" => YaST::YCP::Integer( $syncprov->{'checkpoint'}->{'ops'}),
            "min" => YaST::YCP::Integer( $syncprov->{'checkpoint'}->{'min'})
        }
    }
    if (defined $syncprov->{'sessionlog'} )
    {
        $syncprov->{'sessionlog'} = YaST::YCP::Integer( $syncprov->{'sessionlog'} );
    }
    return $syncprov;
}

BEGIN { $TYPEINFO {WriteSyncProv} = ["function", "boolean" , "integer", ["map", "string", "any" ] ]; }
sub WriteSyncProv
{
    my ( $self, $dbindex, $syncprov) = @_;
    y2milestone("WriteSyncProv");
    y2debug("SyncProv: ".Data::Dumper->Dump([$syncprov]) );
    if (defined $syncprov->{'checkpoint'} )
    {
        $syncprov->{'checkpoint'} = {
            "ops" => YaST::YCP::Integer( $syncprov->{'checkpoint'}->{'ops'}),
            "min" => YaST::YCP::Integer( $syncprov->{'checkpoint'}->{'min'})
        }
    }
    if (defined $syncprov->{'sessionlog'} )
    {
        $syncprov->{'sessionlog'} = YaST::YCP::Integer( $syncprov->{'sessionlog'} );
    }
    if ( ! SCR->Write(".ldapserver.database.{".$dbindex."}.syncprov", $syncprov ) )
    {
        my $err = SCR->Error(".ldapserver");
        $self->SetError( $err->{'summary'}, $err->{'description'} );
        return YaST::YCP::Boolean(0);
    }

    ## Update indexes if the database supports it and if not deleting syncrepl
    if ( keys %$syncprov )
    {
        my $db = $self->ReadDatabase( $dbindex );
            if ( $db->{'type'} eq "bdb" || $db->{'type'} eq "hdb" )
            {
            my $indexes = SCR->Read(".ldapserver.database.{".$dbindex."}.indexes" );
            y2milestone("indexes: ". Data::Dumper->Dump([$indexes]));
            if ( ! $indexes->{'entrycsn'}->{'eq'} )
            {
                $self->ChangeDatabaseIndex($dbindex, { "name" => "entryCSN", "eq" => 1 } );
            }
            if ( ! $indexes->{'entryUUID'}->{'eq'} )
            {
                $self->ChangeDatabaseIndex($dbindex, { "name" => "entryUUID", "eq" => 1 } );
            }
        }
    }
    return YaST::YCP::Boolean(1);
}

BEGIN { $TYPEINFO {ReadSyncRepl} = ["function", [ "list" , [ "map", "string", "any" ] ], "integer" ]; }
sub ReadSyncRepl
{
    my ($self, $index) = @_;
    y2milestone("ReadSyncRepl ", $index);
    my $syncreplList = SCR->Read(".ldapserver.database.{".$index."}.syncrepl" );
    y2debug( "SyncRepl: ".Data::Dumper->Dump([$syncreplList]) );
    if ( ! $syncreplList )
    {
        my $err = SCR->Error(".ldapserver");
        $self->SetError( $err->{'summary'}, $err->{'description'} );
        return undef;
    }
    foreach my $syncrepl (@{$syncreplList})
    {
        if (defined $syncrepl->{'provider'} && defined $syncrepl->{'provider'}->{'port'} )
        {
            $syncrepl->{'provider'}->{'port'} = YaST::YCP::Integer( $syncrepl->{'provider'}->{'port'} );
        }
        if ( defined $syncrepl->{'interval'} )
        {
            $syncrepl->{'interval'}->{'days'} = YaST::YCP::Integer( $syncrepl->{'interval'}->{'days'} );
            $syncrepl->{'interval'}->{'hours'} = YaST::YCP::Integer( $syncrepl->{'interval'}->{'hours'} );
            $syncrepl->{'interval'}->{'mins'} = YaST::YCP::Integer( $syncrepl->{'interval'}->{'mins'} );
            $syncrepl->{'interval'}->{'secs'} = YaST::YCP::Integer( $syncrepl->{'interval'}->{'secs'} );
        }
        if ( defined $syncrepl->{'starttls'} )
        {
            $syncrepl->{'starttls'} = YaST::YCP::Boolean( $syncrepl->{'starttls'} );
        }
    }
    return $syncreplList;
}

BEGIN { $TYPEINFO {WriteSyncRepl} = ["function", "boolean" , "integer", ["map", "string", "any" ] ]; }
sub WriteSyncRepl
{
    my ( $self, $dbindex, $syncrepl) = @_;
    y2milestone("WriteSyncRepl");
    if (defined $syncrepl->{'provider'} && defined $syncrepl->{'provider'}->{'port'} )
    {
        $syncrepl->{'provider'}->{'port'} = YaST::YCP::Integer( $syncrepl->{'provider'}->{'port'} );
    }
    if ( defined $syncrepl->{'interval'} )
    {
        $syncrepl->{'interval'}->{'days'} = YaST::YCP::Integer( $syncrepl->{'interval'}->{'days'} );
        $syncrepl->{'interval'}->{'hours'} = YaST::YCP::Integer( $syncrepl->{'interval'}->{'hours'} );
        $syncrepl->{'interval'}->{'mins'} = YaST::YCP::Integer( $syncrepl->{'interval'}->{'mins'} );
        $syncrepl->{'interval'}->{'secs'} = YaST::YCP::Integer( $syncrepl->{'interval'}->{'secs'} );
    }
    if ( defined $syncrepl->{'starttls'} )
    {
        $syncrepl->{'starttls'} = YaST::YCP::Boolean( $syncrepl->{'starttls'} );
    }
    y2debug("SyncRepl: ".Data::Dumper->Dump([$syncrepl]) );
    if ( ! SCR->Write(".ldapserver.database.{".$dbindex."}.syncrepl", $syncrepl ) )
    {
        my $err = SCR->Error(".ldapserver");
        $self->SetError( $err->{'summary'}, $err->{'description'} );
        return YaST::YCP::Boolean(0);
    }
    
    ## Update indexes if the database supports it and if not deleting syncrepl
    if ( keys %$syncrepl )
    {
        my $db = $self->ReadDatabase( $dbindex );
            if ( $db->{'type'} eq "bdb" || $db->{'type'} eq "hdb" )
            {
            my $indexes = SCR->Read(".ldapserver.database.{".$dbindex."}.indexes" );
            y2milestone("indexes: ". Data::Dumper->Dump([$indexes]));
            if ( ! $indexes->{'entrycsn'}->{'eq'} )
            {
                $self->ChangeDatabaseIndex($dbindex, { "name" => "entryCSN", "eq" => 1 } );
            }
            if ( ! $indexes->{'entryUUID'}->{'eq'} )
            {
                $self->ChangeDatabaseIndex($dbindex, { "name" => "entryUUID", "eq" => 1 } );
            }
        }
    }
    return YaST::YCP::Boolean(1);
}

##
 # Remove the Syncrepl Configuration matching the supplied URI from all databases
 #
 # @param The LDAP Url of the syncrepl consumer configuration to be deleted
 #
 # @return boolean True on success
 #
BEGIN { $TYPEINFO {RemoveMMSyncrepl} = ["function", "boolean", "string" ]; }
sub RemoveMMSyncrepl
{
    my ( $self, $uri ) = @_;

    my $dbs = $self->ReadDatabaseList();
    for ( my $i=0; $i < scalar(@{$dbs})-1; $i++)
    {
        my $type = $dbs->[$i+1]->{'type'};
        if ( $type eq "config" || $type eq "bdb" || $type eq "hdb" )
        {
            SCR->Write(".ldapserver.database.{".$i."}.syncrepl.del", $uri );
        }
        # Disable MirrorMode if needed
        my $syncrepl = SCR->Read(".ldapserver.database.{".$i."}.syncrepl" );
        if ( scalar( @{$syncrepl} ) <= 1 )
        {
            SCR->Write(".ldapserver.database.{".$i."}.mirrormode", YaST::YCP::Boolean(0) );
        }
    }
    SCR->Execute(".ldapserver.commitChanges" );

    return YaST::YCP::Boolean(1);
}

BEGIN { $TYPEINFO {ReadUpdateRef} = ["function", [ "map" , "string", "any" ], "integer" ]; }
sub ReadUpdateRef
{
    my ($self, $index) = @_;
    y2milestone("ReadUpdateRef ", $index);
    my $updateref = SCR->Read(".ldapserver.database.{".$index."}.updateref" );
    y2debug( "SyncRepl: ".Data::Dumper->Dump([$updateref]) );
    if ( defined $updateref->{'port'} )
    {
        $updateref->{'port'} = YaST::YCP::Integer( $updateref->{'port'} );
    }
    return $updateref;
}

BEGIN { $TYPEINFO {WriteUpdateRef} = ["function", "boolean" , "integer", ["map", "string", "any" ] ]; }
sub WriteUpdateRef
{
    my ( $self, $dbindex, $updateref) = @_;
    y2milestone("WriteUpdateref");
    if ( defined $updateref->{'port'} )
    {
        $updateref->{'port'} = YaST::YCP::Integer( $updateref->{'port'} );
    }
    y2debug("Updateref: ".Data::Dumper->Dump([$updateref]) );
    if ( ! SCR->Write(".ldapserver.database.{".$dbindex."}.updateref", $updateref ) )
    {
        my $err = SCR->Error(".ldapserver");
        $self->SetError( $err->{'summary'}, $err->{'description'} );
        return YaST::YCP::Boolean(0);
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

BEGIN { $TYPEINFO {IsSchemaDeletable} = ["function", "boolean", "string" ]; }
sub IsSchemaDeletable
{
    my ($self, $name) = @_;
    my $deletableSchema = SCR->Read(".ldapserver.schema.deletable" );

    if ( grep( /^$name$/, @{$deletableSchema} ) )
    {
        return YaST::YCP::Boolean(1);
    }
    return YaST::YCP::Boolean(0);
}

BEGIN { $TYPEINFO {RemoveFromSchemaList} = ["function", "boolean", "string" ]; }
sub RemoveFromSchemaList
{
    my ($self, $name) = @_;

    my $rc = SCR->Write(".ldapserver.schema.remove", $name);

    return $rc;
}

BEGIN { $TYPEINFO {ValidateDn} = ["function", "boolean", "string" ]; }
sub ValidateDn
{
    my ($self, $dn ) = @_;
    if ( ! defined X500::DN->ParseRFC2253($dn) )
    {
        return 0;
    }
    return 1;
}

sub IsSubordinate
{
    my ($self, $base, $child) = @_;
    my $baseDN = X500::DN->ParseRFC2253($base);
    if(! defined $baseDN) {
        $self->SetError("\"". $base ."\" ". _("is not a valid LDAP DN."), "");
        return undef;
    }
    if ( $baseDN->hasMultivaluedRDNs() )
    {
        $self->SetError("\"". $base ."\" ". _("has multivalued RDNs."), "");
        return undef;
    }
    my $childDN = X500::DN->ParseRFC2253($child);
    if(! defined $childDN) {
        $self->SetError( "\"". $child ."\" ". _("is not a valid LDAP DN."), "");
        return undef;
    }
    if ( $childDN->hasMultivaluedRDNs() )
    {
        $self->SetError( "\"". $child ."\" ". _("has multivalued RDNs."), "");
        return undef;
    }
    my @base_rdns = $baseDN->getRDNs();
    my @child_rdns =  $childDN->getRDNs();
    for( my $i=0; $i < scalar(@base_rdns) ; $i++ )
    {
        y2milestone("Base RDN: ".$base_rdns[$i]->getRFC2253String()." child RDN: ".$child_rdns[$i]->getRFC2253String() );
        if ( $base_rdns[$i]->getRFC2253String() ne $child_rdns[$i]->getRFC2253String() )
        {
            return 0;
        }
    }
    return 1;
}

##
 # Check whether the object named be the supplied LDAP DN can be auto-created.
 # @returns 0 in case of success,
 #         <0 if the supplied DN is invalid
 #         >0 if autocreation is not possible
 #
BEGIN { $TYPEINFO {CheckSuffixAutoCreate} = ["function", "integer", "string" ]; }
sub CheckSuffixAutoCreate
{
    my ($self, $suffix) = @_;
    my $object = X500::DN->ParseRFC2253($suffix);
    my @attr = $object->getRDN($object->getRDNs()-1)->getAttributeTypes();
    my $val = $object->getRDN($object->getRDNs()-1)->getAttributeValue($attr[0]);
    if(!defined $attr[0] || !defined $val)
    {
        y2error("Error while extracting RDN values");
        $self->SetError( _("Invalid LDAP DN: \""). $suffix. _("\", can't extract RDN values"));
        return -1;
    }
    if( (lc($attr[0]) eq "ou") || ( lc($attr[0]) eq "o") || ( lc($attr[0]) eq "l") ||
        ( lc($attr[0]) eq "st") || ( lc($attr[0]) eq "dc") ) {
        return 0;
    } elsif( lc($attr[0]) eq "c") {
        if($val !~ /^\w{2}$/) {
            $self->SetError( _("The value of the \"c\" Attribute must contain a valid ISO-3166 country 2-letter code."), "");
            y2error("The countryName must be an ISO-3166 country 2-letter code.");
            return -1;
        }
        return 0;
    } else {
        y2error("First part of suffix must be c=, st=, l=, o=, ou= or dc=.");
        $self->SetError( _("First part of suffix must be c=, st=, l=, o=, ou= or dc=."), "");
        return 1;
    }
}

BEGIN { $TYPEINFO {CheckDatabase} = ["function", "boolean", [ "map" , "string", "any"] ]; }
sub CheckDatabase
{
    my ($self, $db) = @_;
    y2milestone("CheckDatabase");
    my $suffix_object = X500::DN->ParseRFC2253($db->{'suffix'});
    if(! defined $suffix_object) {
        $self->SetError( _("Base DN") ." \"". $db->{'suffix'} ."\" ". _("is not a valid LDAP DN."), "");
        return 0;
    }
    elsif ( $suffix_object->hasMultivaluedRDNs() )
    {
        $self->SetError( _("Base DN") ." \"". $db->{'suffix'} ."\" ". _("has multivalued RDNs. This is not supported in this YaST Module."), "");
        return 0;
    }


    if ( $db->{'rootdn'} ne "" )
    {
        my $object = X500::DN->ParseRFC2253($db->{'rootdn'});
        if(! defined $object) {
            $self->SetError(_("Root DN"). " \"". $db->{'rootdn'} ."\" ". _("is not a valid LDAP DN."), "");
            return 0;
        }
        elsif ( $object->hasMultivaluedRDNs() )
        {
            $self->SetError(_("Root DN"). " \"". $db->{'rootdn'} ."\" ". 
                            _("has multivalued RDNs. This is not supported in this YaST Module."), "");
            return 0;
        }

        my $rc =  $self->IsSubordinate( $db->{'suffix'}, $db->{'rootdn'} );
        if ( ! defined $rc || $rc == 0 )
        {
            $self->SetError(_("The Root DN must be a child object of the Base DN."), "");
            return 0;
        }
    }
    return 1;
}


BEGIN { $TYPEINFO {AddDatabase} = ["function", "boolean", "integer", [ "map" , "string", "any"], "boolean", "boolean" ]; }
sub AddDatabase
{
    my ($self, $index, $db, $createDir, $createBase) = @_;
    if ( ! $self->CheckDatabase($db) )
    {
        return 0;
    }
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
    if ( ! defined  $db->{'rootpw'} )
    {
        $db->{'rootpw'} = $self->HashPassword($db->{'pwenctype'}, $db->{'rootpw_clear'} );
    }
    if ( $index == 0 )
    {
        # calculate new database index
        my $dbList = $self->ReadDatabaseList();
        $index =  scalar(@{$dbList}) - 1;
        foreach my $listitem (@{$dbList} )
        {
            if ( $listitem->{'suffix'} ne "" )
            {
                $rc = $self->IsSubordinate( $listitem->{'suffix'}, $db->{'suffix'} );
                if ( ! defined $rc )
                {
                    return 0;
                }
                elsif( $rc )
                {
                    y2milestone( $db->{'suffix'}. " is subordinate to " .  $listitem->{'suffix'} );
                    y2milestone( "New index: ". $listitem->{'index'} );
                    $index = $listitem->{'index'};
                    last;
                }
            }
        }
    }

    # Set defaults for caching and checkpoint
    if (! defined $db->{'entrycache'} )
    {
        $db->{'entrycache'} = YaST::YCP::Integer(10000);
    }
    else
    {
        $db->{'entrycache'} = YaST::YCP::Integer($db->{'entrycache'});
    }
    if (! defined $db->{'idlcache'} )
    {
        $db->{'idlcache'} = YaST::YCP::Integer(30000);
    }
    else
    {
        $db->{'idlcache'} = YaST::YCP::Integer($db->{'idlcache'});
    }
    if (! defined $db->{'checkpoint'} )
    {
        $db->{'checkpoint'} = [ YaST::YCP::Integer(1024), YaST::YCP::Integer(5) ];
    }
    else
    {
        $db->{'checkpoint'} = [ YaST::YCP::Integer($db->{'checkpoint'}->[0]), YaST::YCP::Integer($db->{'checkpoint'}->[1]) ];
    }

    $rc = SCR->Write(".ldapserver.database.new.{$index}", $db);
    if(! $rc ) {
        my $err = SCR->Error(".ldapserver");
        y2error("Adding Database failed: ".$err->{'summary'}." ".$err->{'description'});
        $self->SetError( $err->{'summary'}, $err->{'description'} );
        return 0;
    }
    # default indexing
    foreach my $idx ( @$defaultIndexes )
    {
        $self->ChangeDatabaseIndex($index, $idx );
    }

    # add default ACLs
    $rc = SCR->Write(".ldapserver.database.{$index}.acl", $defaultDbAcls );
    if(! $rc ) {
        my $err = SCR->Error(".ldapserver");
        y2error("Adding default ACLs failed: ".$err->{'summary'}." ".$err->{'description'});
        $self->SetError( $err->{'summary'}, $err->{'description'} );
        return 0;
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

    if ( $createBase ) {
        push @added_databases, $db->{'suffix'};
        $self->WriteAuthInfo( $db->{'suffix'},
                        { bind_dn => $db->{'rootdn'},
                          bind_pw => $db->{'rootpw_clear'} } );
    }
    return 1;
}

BEGIN { $TYPEINFO {UpdateDatabase} = ["function", "boolean", "integer", [ "map" , "string", "any"] ]; }
sub UpdateDatabase 
{
    my ($self, $index, $changes) = @_;
    y2milestone( "UpdateDatabase");
    if ( defined $changes->{'entrycache'} )
    {
        $changes->{'entrycache'} = YaST::YCP::Integer( $changes->{'entrycache'} );
    }
    if ( defined $changes->{'idlcache'} )
    {
        $changes->{'idlcache'} = YaST::YCP::Integer( $changes->{'idlcache'} );
    }
    if ( defined $changes->{'checkpoint'} )
    {
        $changes->{'checkpoint'}->[0] = YaST::YCP::Integer( $changes->{'checkpoint'}->[0] );
        $changes->{'checkpoint'}->[1] = YaST::YCP::Integer( $changes->{'checkpoint'}->[1] );
    }
    if ( defined $changes->{'secure_only'} )
    {
        $changes->{'secure_only'} = YaST::YCP::Boolean( $changes->{'secure_only'} );
    }
    y2debug( Data::Dumper->Dump([$changes]) );

    my $rc = SCR->Write(".ldapserver.database.{".$index."}", $changes);
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

##
 # Generates a random password 
 #
 # @return A random password string
 #
BEGIN { $TYPEINFO {GenerateRandPassword} = ["function", "string" ] ; }
sub GenerateRandPassword
{
    my $length=12;
    my @chars=('a'..'z','A'..'Z','0'..'9','_');
    my $randpw;
    foreach (1..$length) 
    {
            # rand @chars will generate a random 
            # number between 0 and scalar @chars
            $randpw .= $chars[rand @chars];
    }
    return $randpw;
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

##
 # Store Authentication Information for a specific database
 # @param String containing the database suffix
 # @param Map with the keys "bind_dn" and "bind_pw" containing the
 #        DN and Password, that can be used to autheticate against 
 #        the database
 # @return true
 #
BEGIN { $TYPEINFO {WriteAuthInfo} = ["function", "boolean", "string", [ "map", "string", "string" ] ]; }
sub WriteAuthInfo
{
    my ( $self, $suffix, $db_auth ) = @_;
    y2milestone("WriteAuthinfo $suffix");
    $auth_info->{$suffix} = $db_auth;
    return 1;
}

##
 # Get Authentication Information for a specific database
 # @param String containing the database suffix
 # @return A map with the keys "bind_dn" and "bind_pw" or
 #         undef
 #
BEGIN { $TYPEINFO {ReadAuthInfo} = ["function", ["map", "string", "string"], "string" ]; }
sub ReadAuthInfo
{
    my ( $self, $suffix) = @_;
    y2milestone("ReadAuthinfo $suffix");
    return $auth_info->{$suffix};
}

##
 # Set the default Password Policy Object for a database
 # the object is create/modified during Write() using the
 # credentials the were set (with WriteAuthInfo()) for the 
 # specified database
 # @param String containing the database suffix
 # @param String containing the DN of the Password Policy Object
 # @param A map containing the LDAP entry of the Password Policy
 #        object
 # @return true
 #
BEGIN { $TYPEINFO {WritePpolicyDefault} = ["function", "boolean", "string", "string", [ "map", "string", "any" ] ]; }
sub WritePpolicyDefault
{
    my ( $self, $suffix, $dn, $ppolicy ) = @_;
    y2milestone("WritePpolicyDefault $suffix $dn");
    y2debug("WritePpolicyDefault ". Data::Dumper->Dump([$ppolicy]) );
    if ( ! defined $ppolicy->{'objectClass'} )
    {
        $ppolicy->{'objectClass'} = [ "namedObject", "pwdPolicy" ];
    }
    if ( ! defined $ppolicy->{'pwdAttribute'} )
    {
        $ppolicy->{'pwdAttribute'} = [ "userPassword" ];
    }
    $ppolicy_objects->{$suffix} = { dn => $dn, ppolicy => $ppolicy } ;
    return 1;
}

##
 # Get the default Password Policy object of a specific database
 # @returns a Map with the keys "dn" and "ppolicy" 
 #  
BEGIN { $TYPEINFO {ReadPpolicyDefault} = ["function", ["map", "string", "any"], "string" ]; }
sub ReadPpolicyDefault
{
    my ( $self, $suffix ) = @_;
    y2milestone("ReadPpolicyDefault $suffix");
    y2milestone("ReadPpolicyDefault ". Data::Dumper->Dump([$ppolicy_objects->{$suffix}]) );
    return $ppolicy_objects->{$suffix}
}

BEGIN { $TYPEINFO {SetupRemoteForReplication} = ["function",  "boolean" ]; }
sub SetupRemoteForReplication
{
    my ( $self ) = @_;

    if ( $self->ReadSetupMirrorMode() )
    {
        y2milestone("Assigning new ServerID");
        $self->AssignServerId( $syncreplbaseconfig->{'provider'}->{'target'} );
        $self->AssignServerId();
    }

    my $dbs = $self->ReadDatabaseList();
    for ( my $i=0; $i < scalar(@{$dbs})-1; $i++)
    {
        y2milestone("Checking SyncProvider Overlay configuration");
        my $type = $dbs->[$i+1]->{'type'};
        my $suffix = $dbs->[$i+1]->{'suffix'};
        if ( $type eq "config" || $type eq "bdb" || $type eq "hdb" )
        {
            my $db = SCR->Read(".ldapserver.database.{".$i."}" );
            my $prv = SCR->Read(".ldapserver.database.{".$i."}.syncprov" );
            y2debug("Database $i ". Data::Dumper->Dump([ $prv ]) );
            if ( keys %{$prv} == 0 )
            {
                y2milestone("Database $i needs syncprov overlay");
                y2milestone("Enabling syncrepl provider overlay on database $i");
                my $syncprov = { 'enabled' => 1, 
                                 'checkpoint' => { 'ops' => YaST::YCP::Integer(100),
                                                  'min' => YaST::YCP::Integer(5)
                                                }
                                };
                SCR->Write(".ldapserver.database.{".$i."}.syncprov", $syncprov);
            }
        }
    }

    for ( my $i=0; $i < scalar(@{$dbs})-1; $i++)
    {
        y2milestone("Checking SyncConsumer configuration");
        my $type = $dbs->[$i+1]->{'type'};
        my $suffix = $dbs->[$i+1]->{'suffix'};
        if ( $type eq "config" || $type eq "bdb" || $type eq "hdb" )
        {
            my $conslist = SCR->Read(".ldapserver.database.{".$i."}.syncrepl" );
            my $needsyncrepl = 1;
            my $needsyncreplMM = 1;
            my %syncReplMM = %{$syncreplbaseconfig};
            my $mmprovider = { 'protocol' => $syncreplbaseconfig->{'provider'}->{'protocol'},
                               'target'   => $self->ReadHostnameFQ(),
                               'port'     => $syncreplbaseconfig->{'provider'}->{'port'}
                             };
            $syncReplMM{'provider'} = $mmprovider;
            $syncReplMM{'basedn'} = $suffix;
            y2milestone("MM syncrepl: ". Data::Dumper->Dump( [\%syncReplMM] ));
            foreach my $cons ( @{$conslist} )
            {
                if ( SyncReplMatch( $cons, $syncreplbaseconfig ) )
                {
                    y2milestone("Syncrepl defintion already present");
                    $needsyncrepl = 0;
                }
                if ( $self->ReadSetupMirrorMode() )
                {
                    if ( SyncReplMatch( $cons, \%syncReplMM ) )
                    {
                        y2milestone("Syncrepl defintion for MirrorMode already present");
                        $needsyncreplMM = 0;
                    }
                }
                else
                {
                    $needsyncreplMM = 0;
                }
                if ( !$needsyncreplMM && !$needsyncrepl )
                {
                    last;
                }
            }
            if ( $needsyncrepl )
            {
                y2milestone("Adding syncrepl consumer configuration for database $i");
                $syncreplbaseconfig->{'basedn'} = $suffix;
                SCR->Write(".ldapserver.database.{".$i."}.syncrepl.add", $syncreplbaseconfig );
            }
            if ( $self->ReadSetupMirrorMode() )
            {
                SCR->Write(".ldapserver.database.{".$i."}.mirrormode", YaST::YCP::Boolean(1) );
                # Remove any existing updateRef, they don't make sense in a mirrormode setup
                SCR->Write(".ldapserver.database.{".$i."}.updateref", {} );
                if ( $needsyncreplMM )
                {
                    my $mmprovider = { 'protocol' => $syncreplbaseconfig->{'provider'}->{'protocol'},
                                       'target'   => $self->ReadHostnameFQ(),
                                       'port'     => $syncreplbaseconfig->{'provider'}->{'port'}
                                     };
                    $syncReplMM{'provider'} = $mmprovider;
                    $syncReplMM{'basedn'} = $suffix;
                    y2milestone("Database $i needs MM syncrepl.". Data::Dumper->Dump( [\%syncReplMM] ));

                    SCR->Write(".ldapserver.database.{".$i."}.syncrepl.add", \%syncReplMM );
                }
            }
        }
    }

    if ( ! $self->ReadSetupMirrorMode() )
    {
        for ( my $i=0; $i < scalar(@{$dbs})-1; $i++)
        {
            y2milestone("Checking Update Referral");
            my $type = $dbs->[$i+1]->{'type'};
            my $suffix = $dbs->[$i+1]->{'suffix'};
            if ( $type eq "config" || $type eq "bdb" || $type eq "hdb" )
            {
                my $updateref = SCR->Read(".ldapserver.database.{".$i."}.updateref" );
                if ( ! defined $updateref  )
                {
                    y2milestone("Adding Update Referral");
                    SCR->Write(".ldapserver.database.{".$i."}.updateref",
                               $syncreplbaseconfig->{'provider'} );
                }
            }
        }
    }

    for ( my $i=0; $i < scalar(@{$dbs})-1; $i++)
    {
        y2milestone("Checking Database ACLs");
        my $type = $dbs->[$i+1]->{'type'};
        my $suffix = $dbs->[$i+1]->{'suffix'};
        if ( $type eq "config" || $type eq "bdb" || $type eq "hdb" )
        {
            my $db = SCR->Read(".ldapserver.database.{".$i."}" );
            my $needsacl = 0;
            if ( lc($db->{'rootdn'}) eq lc($syncreplbaseconfig->{'binddn'}) )
            {
                y2milestone("Repl DN \"".$syncreplbaseconfig->{'binddn'}. "\" is rootdn of database $i. No ACL needed");
            }
            else
            {
                my $acl = SCR->Read(".ldapserver.database.{".$i."}.acl" );
                if ( ! $acl )
                {
                    next;
                }
                y2debug("Database $i acl:".  Data::Dumper->Dump([ $acl ]) );
                my $needacl = 1;
                foreach my $rule ( @{$acl} )
                {
                    my $wholedb=0;
                    if ( keys %{$rule->{'target'}} == 0 )
                    {
                        $wholedb=1;
                    }
                    elsif ( defined $rule->{'target'}->{'dn'} && 
                            $rule->{'target'}->{'dn'}->{'style'} eq "subtree" &&
                            lc($rule->{'target'}->{'dn'}->{'value'}) eq lc($suffix)
                          )
                    {
                        $wholedb=1;
                    }
                    else
                    {
                        # rule doesn't match the whole database
                        $wholedb=0;
                        last;
                        
                    }
                    if ($wholedb)
                    {
                        # this rule matches all db entries, check if it gives
                        # at least read access to the provided syncrepl id
                        foreach my $access ( @{$rule->{'access'}} )
                        {
                            if ( $access->{'type'} eq "dn.base" && 
                                 lc($access->{'value'}) eq lc($syncreplbaseconfig->{'binddn'} ) &&
                                 ($access->{'level'} eq "read" || $access->{'level'} eq "write")
                               )
                            {
                                y2milestone("Found matching ACL in database $i");
                                $needacl = 0;
                                last;
                            }
                        }
                        if (! $needacl)
                        {
                            last;
                        }
                    }
                }
                if ( $needacl )
                {
                    y2milestone("Adding ACL for syncrepl to database $i");
                    my @syncacl = ({
                            'target' => {},
                            'access' => [
                                    { 'type' => "dn.base",
                                      'value' => $syncreplbaseconfig->{'binddn'},
                                      'level' => "read",
                                      'control' => "" },
                                    { 'type' => "*",
                                      'value' => "",
                                      'level' => "",
                                      'control' => "break" }
                                ]
                        });
                    my $acl = SCR->Read(".ldapserver.database.{".$i."}.acl" );
                    push @syncacl, (@$acl);
                    my $rc = SCR->Write(".ldapserver.database.{".$i."}.acl", \@syncacl );
                }
            }
        }
    }
    for ( my $i=0; $i < scalar(@{$dbs})-1; $i++)
    {
        y2milestone("Checking Database Limits");
        my $type = $dbs->[$i+1]->{'type'};
        my $suffix = $dbs->[$i+1]->{'suffix'};
        if ( $type eq "config" || $type eq "bdb" || $type eq "hdb" )
        {
            my $db = SCR->Read(".ldapserver.database.{".$i."}" );
            my $needslimit = 1;
            if ( lc($db->{'rootdn'}) eq lc($syncreplbaseconfig->{'binddn'}) )
            {
                y2milestone("Repl DN \"".$syncreplbaseconfig->{'binddn'}. "\" is rootdn of database $i. No limit needed");
            }
            else
            {
                my $limits = SCR->Read(".ldapserver.database.{".$i."}.limits" );
                y2milestone("Database $i limits:".  Data::Dumper->Dump([ $limits ]) );
                foreach my $limit (@$limits)
                {
                    if ( $limit->{'selector'} eq "dn.exact=\"".$syncreplbaseconfig->{'binddn'}."\"" )
                    {
                        my $limitvals = $limit->{'limits'};
                        foreach my $val (@$limitvals )
                        {
                            if ( $val->{'type'} eq "size.soft" && $val->{'value'} eq "unlimited" )
                            {
                                y2milestone("limit already present, no need to add");
                                $needslimit = 0;
                                last;
                            }
                        }
                        if (! $needslimit )
                        {
                            last;
                        }
                    }
                }
                if ($needslimit)
                {
                    y2milestone("Setting sizelimit for syncrepuser to unlimited.");
                    my @newlimits = ( { 'selector' => "dn.exact=\"".$syncreplbaseconfig->{'binddn'}."\"",
                                        'limits'   => [ { 'type'  => "size.soft",
                                                          'value' => "unlimited" } ] } );
                    push @newlimits, @$limits;
                    SCR->Write(".ldapserver.database.{".$i."}.limits", \@newlimits );
                }
            }
        }
    }
    y2milestone("Updating remote configuration");
    SCR->Execute(".ldapserver.commitChanges" );
    $masterldif = SCR->Execute(".ldapserver.dumpConfDb" );
    SCR->Execute(".ldapserver.reset" );
    
    $globals_initialized = 0;
    $self->CreateSyncReplAccount();
    $syncreplbaseconfig->{'binddn'} = "cn=config";
    $syncreplbaseconfig->{'credentials'} = $auth_info->{'cn=config'}->{'bind_pw'};
    $syncreplbaseconfig->{'basedn'} = "cn=config";

    return 1;
}

BEGIN { $TYPEINFO {WriteSyncreplBaseConfig} = ["function",  "boolean", ["map", "string", "any"] ]; }
sub WriteSyncreplBaseConfig
{
    my ($self, $syncrepl ) = @_;
    $syncreplbaseconfig = $syncrepl;

    if ( defined $syncreplbaseconfig->{'provider'} )
    {
        if ( defined $syncreplbaseconfig->{'provider'}->{'port'} )
        { 
            $syncreplbaseconfig->{'provider'}->{'port'} = YaST::YCP::Integer($syncreplbaseconfig->{'provider'}->{'port'} ); 
        }
    }
    if ( defined $syncreplbaseconfig->{'starttls'} )
    {
        $syncreplbaseconfig->{'starttls'} = YaST::YCP::Boolean($syncreplbaseconfig->{'starttls'} );
    }
    return 1;
}

BEGIN { $TYPEINFO {ReadSyncreplBaseConfig} = ["function",  ["map", "string", "any"] ]; }
sub ReadSyncreplBaseConfig
{
    my ($self, $syncrepl ) = @_;
    return $syncreplbaseconfig;
    return 1;
}

##
 # Set "true" here if we are setting up a Syncrepl Slave server currently
 # (this function is only useful for the installation wizards)
 #
 # @return true
 #
BEGIN { $TYPEINFO {WriteSetupSlave} = ["function",  "boolean", "boolean"]; }
sub WriteSetupSlave
{
    my ($self, $value) = @_;
    $setupSyncreplSlave=$value;
}

##
 # @return true, if the current setup will creat a Syncrepl Slave server
 #         false otherwise
 #
BEGIN { $TYPEINFO {ReadSetupSlave} = ["function",  "boolean" ]; }
sub ReadSetupSlave
{
    return $setupSyncreplSlave;
}

##
 # Set "true" here if we are setting up a Syncrepl Master server currently
 # (this function is only useful for the installation wizards)
 #
 # @return true
 #
BEGIN { $TYPEINFO {WriteSetupMaster} = ["function",  "boolean", "boolean"]; }
sub WriteSetupMaster
{
    my ($self, $value) = @_;
    $setupSyncreplMaster=$value;
}

##
 # @return true, if the current setup will create a Syncrepl Master server
 #         false otherwise
 #
BEGIN { $TYPEINFO {ReadSetupMaster} = ["function",  "boolean" ]; }
sub ReadSetupMaster
{
    return $setupSyncreplMaster;
}

##
 # Set "true" here if we are setting up a Syncrepl Master for acting as a
 # MirrorMode Node. (it will result in a olcServerId being created)
 # (this function is only useful for the installation wizards)
 #
 # @return true
 #
BEGIN { $TYPEINFO {WriteSetupMirrorMode} = ["function",  "boolean", "boolean"]; }
sub WriteSetupMirrorMode
{
    my ($self, $value) = @_;
    $setupMirrorMode=$value;
}

##
 # @return true, if the current setup will create a Syncrepl Mirror Mode Master
 #         false otherwise
 #
BEGIN { $TYPEINFO {ReadSetupMirrorMode} = ["function",  "boolean" ]; }
sub ReadSetupMirrorMode
{
    return $setupMirrorMode;
}

##
 # @return true, if the currently connected server is member of a mirrormode setup
 #
BEGIN { $TYPEINFO {HasMirrorMode} = ["function",  "boolean" ]; }
sub HasMirrorMode
{
    my $self = shift;
    return SCR->Read(".ldapserver.database.{0}.mirrormode" );
}

##
 # Initializes the ldapserver agent to connect to a remote cn=config database
 # @param A Map containing the details for the remote connections. Required keys:
 #      "provider": A Map with the keys "protocol" (can be "ldap" or "ldaps"), 
 #                  target (contains the hostname of the destination server) and
 #                  port (the port number to connect to).
 #      "starttls": A boolean to flag whether to use TLS
 #      "credentials" : The password for the "cn=config" account
 #
 # @return true on success, false on failure
 #
BEGIN { $TYPEINFO {InitRemoteConnection} = ["function",  "boolean", ["map", "string", "any"] ]; }
sub InitRemoteConnection
{
    my ( $self, $param) = @_;
    $param->{'target'}->{'port'} = YaST::YCP::Integer($param->{'target'}->{'port'});
    $param->{'starttls'} = YaST::YCP::Boolean($param->{'starttls'});

    $param->{'configcred'} = $param->{'credentials'};
    my $rc = SCR->Execute(".ldapserver.init", $param );
    if ( ! $rc )
    {
        my $err = SCR->Error(".ldapserver");
        $self->SetError( $err->{"summary"}, $err->{"description"} );
        SCR->Execute(".ldapserver.reset" );
    }
    return $rc;
}

##
 # Read the TLS Settings from the currently connected cn=config database and checks if 
 # the local TLS Setup is suited for replicating that config, by checking if the required 
 # Certificate and CA files a present and by trying to verify the remote servers certificate
 # with the locally installed CA.
 # @param A Map with the keys "target" (contains the hostname of the destination server) and
 #        "port" (the port number to connect to).
 #
BEGIN { $TYPEINFO {VerifyTlsSetup} = ["function",  "boolean", ["map", "string", "any" ] ]; }
sub VerifyTlsSetup
{
    my ($self, $param ) = @_;
    my $remoteuri = "ldap://".$param->{'target'}.":".$param->{'port'};
    my $tls = $self->ReadTlsConfig();
    y2milestone("TlsConfig ". Data::Dumper->Dump([$tls]) );
    if ( SCR->Read(".target.size", $tls->{"caCertFile"}) <= 0)
    {
        $self->SetError( _("CA Certificate File: \"") .  $tls->{"caCertFile"}. _("\" does not exist."), "");
        return 0;
    }
    else
    {
        # Check if this is the correct CA for verifing the remote server's certificate
        y2milestone("ssl check command: $ssl_check_command \"".$remoteuri."\" ".$tls->{"caCertFile"} );
        my $rc = SCR->Execute( '.target.bash_output', $ssl_check_command." \"".$remoteuri."\" ".$tls->{"caCertFile"} );
        if ( $rc->{'exit'} != 0 )
        {
            $self->SetError( _("Error while trying to verify the Server Certificate of the Provider server.\n").
                             _("Please make sure that \"".$tls->{"caCertFile"}."\" constains the correct\nCA file to verify the remote Server Certificate."),
                             $rc->{'stderr'} );
            return 0;
        }
    }

    if ( SCR->Read(".target.size", $tls->{"certFile"}) <= 0)
    {
        $self->SetError( _("Certificate File: \""). $tls->{"certFile"}. _(\" does not exist."), "" );
        return 0;
    }
    if ( SCR->Read(".target.size", $tls->{"certKeyFile"}) <= 0)
    {
        $self->SetError( _("Certificate Key File: \""). $tls->{"certKeyFile"} . _("\" does not exist."), "");
        return 0;
    }
    return 1;
}

sub SyncReplMatch
{
    y2milestone("SyncReplMatch");
    my ($syncrepl1, $syncrepl2) = @_;
    my $ret = 1;

    if ( $syncrepl1->{'provider'}->{'target'} ne $syncrepl2->{'provider'}->{'target'} )
    {
        y2debug("Provider Hostname doesn't match");
        $ret = 0;
    }
    elsif ( $syncrepl1->{'provider'}->{'port'} ne $syncrepl2->{'provider'}->{'port'}->value )
    {
        y2debug("Provider Port doesn't match");
        $ret = 0;
    }
    elsif ( $syncrepl1->{'provider'}->{'protocol'} ne $syncrepl2->{'provider'}->{'protocol'} )
    {
        y2debug("Provider Protocol doesn't match");
        $ret = 0;
    }
    elsif ( $syncrepl1->{'binddn'} ne $syncrepl2->{'binddn'} )
    {
        y2debug("binddn doesn't match syncreplbaseconfig");
        $ret = 0;
    }
    elsif ( $syncrepl1->{'credentials'} ne $syncrepl2->{'credentials'} )
    {
        y2debug("credentials don't match syncreplbaseconfig");
        $ret = 0;
    }
    return $ret;
}

1;
# EOF
