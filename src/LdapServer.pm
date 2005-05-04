#! /usr/bin/perl -w
# File:		modules/LdapServer.pm
# Package:	Configuration of ldap-server
# Summary:	LdapServer settings, input and output functions
# Authors:	Andreas Bauer <abauer@suse.de>
#
# $Id$
#
# Representation of the configuration of ldap-server.
# Input and output routines.


package LdapServer;

use strict;

use ycp;
use YaST::YCP qw(Boolean);

use YaPI;
textdomain("ldap-server");

use YaPI::LdapServer;

our %TYPEINFO;

YaST::YCP::Import ("Progress");
YaST::YCP::Import ("Report");
YaST::YCP::Import ("Summary");


##
 # Data was modified?
 #
my $modified = 0;

##
 #
my $proposal_valid = 0;

##
 # Write only, used during autoinstallation.
 # Don't run services and SuSEconfig, it's all done at one place.
 #
my $write_only = 0;

##
 # Data was modified?
 # @return true if modified
 #
BEGIN { $TYPEINFO {Modified} = ["function", "boolean"]; }
sub Modified {
    y2debug ("modified=$modified");
    return $modified;
}

##
 # Data was modified
 #
BEGIN { $TYPEINFO {SetModified} = ["function", "void", "boolean"]; }
sub SetModified {
    $modified = shift;
    y2debug ("modified=$modified");
}

# Settings: Define all variables needed for configuration of ldap-server
# TODO FIXME: Define all the variables necessary to hold
# TODO FIXME: the configuration here (with the appropriate
# TODO FIXME: description)
# TODO FIXME: For example:
#   ##
#    # List of the configured cards.
#    #
#   my @cards = ();
#
#   ##
#    # Some additional parameter needed for the configuration.
#    #
#   my $additional_parameter = 1;


my $dbList = [];

my $database = {};

my $allowList = [];

my $loglevel = 256;

my $tlsSettings = {};

my $configureCommonServerCertificate = 0;

my $commonServerCertificateAvailable = 0;

my $dbListNEW = [];

my $databaseNEW = {};

my $serviceEnabled = 1;

my $useRootPW = 0;

my $importCertificates = {};

my $SLPEnabled = 1;

my $schemaIncludeList = [];


BEGIN { $TYPEINFO{WriteDbList} = ["function", "boolean", ["list", "string"]]; }
sub WriteDbList {
    my $self = shift;
    $dbList = shift;
    return 1;
}

BEGIN { $TYPEINFO{ReadDbList} = ["function", ["list", "string"]]; }
sub ReadDbList {
    my $self = shift;
    return $dbList;
}

BEGIN { $TYPEINFO{WriteDatabase} = ["function", "boolean", ["map", "string", "any"]]; }
sub WriteDatabase {
    my $self = shift;
    $database = shift;
    return 1;
}

BEGIN { $TYPEINFO{ReadDatabase} = ["function", ["map", "string", "any"]]; }
sub ReadDatabase {
    my $self = shift;
    return $database;
}

BEGIN { $TYPEINFO{WriteAllowList} = ["function", "boolean", ["list", "string"]]; }
sub WriteAllowList {
    my $self = shift;
    $allowList = shift;
    return 1;
}
BEGIN { $TYPEINFO{ReadAllowList} = ["function", ["list", "string"]]; }
sub ReadAllowList {
    my $self = shift;
    return $allowList;
}

BEGIN { $TYPEINFO{WriteLoglevel} = ["function", "boolean", "integer"]; }
sub WriteLoglevel {
    my $self = shift;
    $loglevel = shift;
    return 1;
}
BEGIN { $TYPEINFO{ReadLoglevel} = ["function", "integer"]; }
sub ReadLoglevel {
    my $self = shift;
    return $loglevel;
}

BEGIN { $TYPEINFO{WriteTlsSettings} = ["function", "boolean", ["map", "string", "any"]]; }
sub WriteTlsSettings {
    my $self = shift;
    $tlsSettings = shift;
    return 1;
}
BEGIN { $TYPEINFO{ReadTlsSettings} = ["function", ["map", "string", "any"]]; }
sub ReadTlsSettings {
    my $self = shift;
    return $tlsSettings;
}

BEGIN { $TYPEINFO{WriteConfigureCommonServerCertificate} = ["function", "boolean", "boolean"]; }
sub WriteConfigureCommonServerCertificate {
    my $self = shift;
    $configureCommonServerCertificate = shift;
    return 1;
}
BEGIN { $TYPEINFO{ReadConfigureCommonServerCertificate} = ["function", "boolean"]; }
sub ReadConfigureCommonServerCertificate {
    my $self = shift;
    return $configureCommonServerCertificate;
}

BEGIN { $TYPEINFO{ReadCommonServerCertificateAvailable} = ["function", "boolean"]; }
sub ReadCommonServerCertificateAvailable {
    my $self = shift;
    return $commonServerCertificateAvailable;
}

BEGIN { $TYPEINFO{WriteDbListNEW} = ["function", "boolean", ["list", "string"]]; }
sub WriteDbListNEW {
    my $self = shift;
    $dbListNEW = shift;
    return 1;
}

BEGIN { $TYPEINFO{ReadDbListNEW} = ["function", ["list", "string"]]; }
sub ReadDbListNEW {
    my $self = shift;
    return $dbListNEW;
}

BEGIN { $TYPEINFO{WriteDatabaseNEW} = ["function", "boolean", ["map", "string", "any"]]; }
sub WriteDatabaseNEW {
    my $self = shift;
    $databaseNEW = shift;
    return 1;
}
BEGIN { $TYPEINFO{ReadDatabaseNEW} = ["function", ["map", "string", "any"]]; }
sub ReadDatabaseNEW {
    my $self = shift;
    return $databaseNEW;
}

BEGIN { $TYPEINFO{WriteServiceEnabled} = ["function", "boolean", "boolean"]; }
sub WriteServiceEnabled {
    my $self = shift;
    $serviceEnabled = shift;
    return 1;
}
BEGIN { $TYPEINFO{ReadServiceEnabled} = ["function", "boolean"]; }
sub ReadServiceEnabled {
    my $self = shift;
    return $serviceEnabled;
}

BEGIN { $TYPEINFO{WriteUseRootPW} = ["function", "boolean", "boolean"]; }
sub WriteUseRootPW {
    my $self = shift;
    $useRootPW = shift;
    return 1;
}

BEGIN { $TYPEINFO{ReadUseRootPW} = ["function", "boolean"]; }
sub ReadUseRootPW {
    my $self = shift;
    return $useRootPW;
}

BEGIN { $TYPEINFO{WriteImportCertificates} = ["function", "boolean", ["map", "string", "string"]]; }
sub WriteImportCertificates {
    my $self = shift;
    $importCertificates = shift;
    return 1;
}

BEGIN { $TYPEINFO{ReadImportCertificates} = ["function", ["map", "string", "string"]]; }
sub ReadImportCertificates {
    my $self = shift;
    return $importCertificates;
}

BEGIN { $TYPEINFO{WriteSLPEnabled} = ["function", "boolean", "boolean"] }
sub WriteSLPEnabled
{
    my $self = shift;
    $SLPEnabled = shift;
    return 1;
}

BEGIN { $TYPEINFO{ReadSLPEnabled} = ["function", "boolean"] }
sub ReadSLPEnabled
{
    my $self = shift;
    return $SLPEnabled;
}

BEGIN { $TYPEINFO{WriteSchemaIncludeList} = ["function", "boolean", ["list", "string"]] }
sub WriteSchemaIncludeList
{
    my $self = shift;
    $schemaIncludeList = shift;
    return 1;
}

BEGIN { $TYPEINFO{ReadSchemaIncludeList} = ["function", ["list", "string"]] }
sub ReadSchemaIncludeList
{
    my $self = shift;
    return $schemaIncludeList;
}

BEGIN { $TYPEINFO{AddDatabase} = ["function", "boolean", ["map", "string", "any"]]; }
sub AddDatabase {
    my $self = shift;
    my $data = shift;

    if(! defined $data->{suffix} || $data->{suffix} eq "") {
        print STDERR "Wrong suffix\n";
        # error message
        Report->Error(__("Invalid suffix."));        
        return 0;
    }

    if(! defined $data->{database} || !grep( ($_ eq $data->{database}), ("bdb", "ldbm"))) {
        $data->{database} = "bdb";
    }

    if(! defined $data->{rootdn} || $data->{rootdn} eq "" ) {
        $data->{rootdn} = "cn=Administrator,".$data->{suffix};
    }

    if(! defined $data->{passwd} || $data->{passwd} eq "" ) {
        print STDERR "Wrong password\n";
        
        # error message
        Report->Error(__("Invalid password."));
        return 0;
    }
    
    if(! defined $data->{cryptmethod} || !grep( ($_ eq $data->{cryptmethod}), 
                                                ("CRYPT", "SMD5", "SHA", "SSHA", "PLAIN"))) {
        $data->{cryptmethod} = "SSHA";
    }

    if(! defined $data->{directory} || $data->{directory} !~ /^\// ) {
        print STDERR "Wrong directory path\n";

        # error message
        Report->Error(__("Invalid directory path."));
        return 0;
    }
    
    if(! defined $data->{cachesize} || $data->{cachesize} !~ /^\d+$/ ) {
        $data->{cachesize} = 10000;
    }

    if($data->{database} eq "bdb") {
        if(defined $data->{checkpoint} && $data->{checkpoint} ne "") {
            my @cp = split(/\s+/, $data->{checkpoint});
            if(!defined $cp[0] || !defined $cp[1] ||
               $cp[0] !~ /^\d+$/ || $cp[1] !~ /^\d+$/) {
                $cp[0] = "1024";
                $cp[1] = "5";
            }
            $data->{checkpoint} = $cp[0]." ".$cp[1];
        } else {
            $data->{checkpoint} = "1024 5";
        }
    }

    #######################################################

    push @$dbListNEW, $data->{suffix};

    $databaseNEW->{$data->{suffix}}->{database}    = $data->{database};
    $databaseNEW->{$data->{suffix}}->{suffix}      = $data->{suffix};
    $databaseNEW->{$data->{suffix}}->{rootdn}      = $data->{rootdn};
    $databaseNEW->{$data->{suffix}}->{passwd}      = $data->{passwd};
    $databaseNEW->{$data->{suffix}}->{cryptmethod} = $data->{cryptmethod};
    $databaseNEW->{$data->{suffix}}->{directory}   = $data->{directory};
    $databaseNEW->{$data->{suffix}}->{cachesize}   = $data->{cachesize};
    if($data->{database} eq "bdb") {
        $databaseNEW->{$data->{suffix}}->{checkpoint} = $data->{checkpoint};
    }

    $modified = 1;

    return 1;
}

##
 # Read all ldap-server settings
 # @return true on success
 #
BEGIN { $TYPEINFO{Read} = ["function", "boolean"]; }
sub Read {

    # LdapServer read dialog caption
    my $caption = __("Initializing LDAP Server Configuration");

    # TODO FIXME Set the right number of stages
    my $steps = 4;

    my $sl = 0.5;
    sleep($sl);

    # TODO FIXME Names of real stages
    # We do not set help text here, because it was set outside
    Progress->New( $caption, " ", $steps, [
	    # Progress stage 1/3
	    __("Read the database list"),
	    # Progress stage 2/3
	    __("Read the databases"),
	    # Progress stage 3/3
	    __("Read global options")
	], [
	    # Progress step 1/3
	    __("Reading the database list..."),
	    # Progress step 2/3
	    __("Reading the databases..."),
	    # Progress step 3/3
	    __("Reading global options..."),
	    # Progress finished
	    __("Finished")
	],
	""
    );

    # read database
    Progress->NextStage();

    $dbList = YaPI::LdapServer->ReadDatabaseList();

    if(! defined $dbList)
    {
        # Error message
        Report->Error(__("Cannot read the database list."));
    }
    sleep($sl);

    # read another database
    Progress->NextStep();

    foreach my $db (@$dbList) {
        
        $database->{$db} = YaPI::LdapServer->ReadDatabase($db);
        
        if(! defined $database->{$db})
          {
              # Error message
              Report->Error(sprintf(__("Cannot read the database '%s'."), $db));
          }

        if(exists $database->{$db}->{rootpw}) {
            my $rootpw = $database->{$db}->{rootpw};
            delete $database->{$db}->{rootpw};
            
            if($rootpw =~ /^{(\w+)}/) {
                $database->{$db}->{cryptmethod} = uc("$1");
            } else {
                $database->{$db}->{cryptmethod} = "PLAIN";
            }
            #$database->{$db}->{passwd} = undef;
        }

    }
    sleep($sl);

    # read current settings
    Progress->NextStage();
            
    $allowList = YaPI::LdapServer->ReadAllowList();
        
    if(! defined $allowList)
      {
          # Error message
          Report->Error(__("Cannot read the allow list."));
      }
    
    $loglevel = YaPI::LdapServer->ReadLoglevel();
    if(! defined $loglevel)
      {
          # Error message
          Report->Error(__("Cannot read the log level."));
      }

    $schemaIncludeList = YaPI::LdapServer->ReadSchemaIncludeList();
    if( !defined $schemaIncludeList )
    {
          # Error message
          Report->Error( __("Cannot read the schema include list.") );
    }


    $tlsSettings = YaPI::LdapServer->ReadTLS();
    if(! defined $tlsSettings)
      {
          # Error message
          Report->Error(__("Cannot read the TLS settings."));
      }

    $commonServerCertificateAvailable = YaPI::LdapServer->CheckCommonServerCertificate();
    
    $serviceEnabled = YaPI::LdapServer->ReadService();

    $SLPEnabled = YaPI::LdapServer->ReadSLPEnabled();
    $SLPEnabled = 0 if( !defined $SLPEnabled );

    sleep($sl);

    # Progress finished
    Progress->NextStage();
    sleep($sl);
    
    $modified = 0;
    return 1;
}

##
 # Write all ldap-server settings
 # @return true on success
 #
BEGIN { $TYPEINFO{Write} = ["function", "boolean"]; }
sub Write {

    # LdapServer read dialog caption
    my $caption = __("Saving LDAP Server Configuration");

    # TODO FIXME And set the right number of stages
    my $steps = 3;

    my $ret = undef;

    my $sl = 0.5;
    sleep($sl);

    # TODO FIXME Names of real stages
    # We do not set help text here, because it was set outside
    Progress->New($caption, " ", $steps, [
	    # Progress stage 1/3
	    __("Write global settings"),
	    # Progress stage 2/3
	    __("Add new databases"),
	    # Progress stage 3/3
	    __("Edit databases"),
	], [
	    # Progress step 1/3
	    __("Write global settings"),
	    # Progress step 2/3
	    __("Add new databases"),
	    # Progress step 3/3
	    __("Edit databases"),
	    # Progress finished
	    __("Finished")
	],
	""
    );

    # write settings
    Progress->NextStage();

    YaPI::LdapServer->ModifyService($serviceEnabled);
    
    if( $serviceEnabled )
    {
        $ret = YaPI::LdapServer->WriteAllowList($allowList);
        if(! defined $ret) {
            # error message
            Report->Error (__("Cannot write 'allow list'."));
        }
        
        $ret = YaPI::LdapServer->WriteLoglevel($loglevel);
        if(! defined $ret) {
            # error message
            Report->Error (__("Cannot write 'loglevel'."));
        }


        $ret = YaPI::LdapServer->WriteSchemaIncludeList( $schemaIncludeList );
        if(! defined $ret) {
            # error message
            Report->Error (__("Cannot write schema include list."));
        }

        $ret = YaPI::LdapServer->WriteSLPEnabled( $SLPEnabled );
        if(! defined $ret) {
            # error message
            Report->Error (__("Cannot write to '/etc/sysconfig/openldap'."));
        }

        if($configureCommonServerCertificate) {
            
            $ret = YaPI::LdapServer->ConfigureCommonServerCertificate();
            if(! defined $ret) {
                # error message
                Report->Error (__("Cannot write 'TLS Settings'."));
            }
            
        } else 
        {
            if( ( scalar keys %$importCertificates ) > 0 )
            {
                $ret = YaPI::LdapServer->ImportCertificates( $importCertificates );
                if(! defined $ret) {
                    # error message
                    Report->Error (__("Cannot write 'TLS Settings'."));
                    y2error( "importCertificates failed" );
                }
            }
        }
    }

    sleep($sl);

    Progress->NextStage();

    if( $serviceEnabled )
    {
        foreach my $db (@$dbListNEW) {
            
            $ret = YaPI::LdapServer->AddDatabase($databaseNEW->{$db});
            
            if(! defined $ret)
              {
                  # Error message
                  Report->Error( sprintf( __("Cannot add new database '%s'."), $db ) );
                  next;
              }
            
            #add indexes
            $ret = YaPI::LdapServer->AddIndex( $db, {attr=>"objectClass,uidNumber,gidNumber",param=>"eq"} );
            if(! defined $ret)
              {
                  # Error message
                  Report->Error(sprintf(__("Cannot add new database '%s'."), $db));
                  next;
              }
            
            $ret = YaPI::LdapServer->AddIndex( $db, {attr=>"member,mail",param=>"eq,pres"} );
            if(! defined $ret)
              {
                  # Error message
                  Report->Error(sprintf(__("Cannot add new database '%s'."), $db));
                  next;
              }
            
            $ret = YaPI::LdapServer->AddIndex( $db, {attr=>"cn,displayname,uid,sn,givenname",
                                                     param=>"sub,eq,pres"} );
            if(! defined $ret)
              {
                  # Error message
                  Report->Error(sprintf(__("Cannot add new database '%s'."), $db));
                  next;
              }

            $ret = YaPI::LdapServer->RecreateIndex( $db );
            if(! defined $ret)
              {
                  # Error message
                  Report->Error(sprintf(__("Cannot add new database '%s'."), $db));
                  next;
              }
        }
    }
    
    sleep($sl);

    Progress->NextStage();

    if( $serviceEnabled )
    {
        foreach my $db (@$dbList) {
            
            $ret = YaPI::LdapServer->EditDatabase($db, $database->{$db});
            
            if(! defined $ret)
              {
                  # Error message
                  Report->Error(sprintf(__("Cannot write the database '%s'."), $db));
              }

        }
    }

    YaPI::LdapServer->SwitchService($serviceEnabled);

    sleep($sl);


    # Progress finished
    Progress->NextStage();
    sleep($sl);

    return 1;
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

    if(exists $hash->{database}) {
        foreach my $db (keys %{$hash->{database}}) {
            
            if(exists $database->{$db}) {
                $database->{$db} = $hash->{database}->{$db};
            }
        }
    }
    if(exists $hash->{allowList}) {
        $allowList = $hash->{allowList};
    }

    if(exists $hash->{loglevel}) {
        $loglevel = $hash->{loglevel};
    }

    if(exists $hash->{tlsSettings}) {
        $tlsSettings = $hash->{tlsSettings};
    }

    if(exists $hash->{schemaIncludeList}) {
        $schemaIncludeList = $hash->{schemaIncludeList};
    }

    if(exists $hash->{configureCommonServerCertificate}) {
        $configureCommonServerCertificate = $hash->{configureCommonServerCertificate};
    }

    if(exists $hash->{databaseNEW}) {
        foreach my $db (keys %{$hash->{databaseNEW}}) {
            
            if(! $self->AddDatabase($hash->{databaseNEW}->{$db})) {
                return 0;
            }
            
        }
    }
    if(exists $hash->{serviceEnabled}) {
        $serviceEnabled = $hash->{serviceEnabled};
    }
    
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

    #$hash->{dbList} = $dbList;
    #$hash->{dbListNEW} = $dbListNEW;


    $hash->{database} = $database;
    $hash->{allowList} = $allowList;
    $hash->{loglevel} = $loglevel;
    $hash->{tlsSettings} = $tlsSettings;
    $hash->{schemaIncludeList} = $schemaIncludeList;
    $hash->{configureCommonServerCertificate} = $configureCommonServerCertificate;
    $hash->{commonServerCertificateAvailable} = $commonServerCertificateAvailable;
    $hash->{databaseNEW} = $databaseNEW;
    $hash->{serviceEnabled} = $serviceEnabled;

    return $hash;
}

##
 # Create a textual summary and a list of unconfigured cards
 # @return summary of the current configuration
 #
BEGIN { $TYPEINFO{Summary} = ["function", [ "list", "string" ] ]; }
sub Summary {
    # Configuration summary text for autoyast
    my $string = "";

#    if($serviceEnabled) {
#        $string .= __("Start LDAP server with:<br>");
#        $string .= sprintf(__("<b>baseDN</b>: %s<br>"), $dbList->[0]);
#        $string .= sprintf(__("<b>rootDN</b>: %s<br>"), $database->{$dbList->[0]}->{rootdn});
#        if($useRootPW) {
#            $string .= __("<b>password</b>: <root password>");
#        } else {
#            $string .= __("<b>password</b>: ***");
#        }
#    } else {
#        $string .= __("LDAP server not running.");
#    }

    return [ $string ];
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

1;
# EOF
