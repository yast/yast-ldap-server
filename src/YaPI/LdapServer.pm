=head1 NAME

YaPI::LdapServer

=head1 PREFACE

This package is the public Yast2 API to managing a LDAP Server.

=head1 SYNOPSIS

use YaPI::LdapServer

=head1 DESCRIPTION

=over 2

=cut


package YaPI::LdapServer;

BEGIN {
    push @INC, '/usr/share/YaST2/modules/';
}

our $VERSION="1.0.0";

use strict;
use vars qw(@ISA);

use YaST::YCP;
use ycp;

use Locale::gettext;
use POSIX ();     # Needed for setlocale()

POSIX::setlocale(LC_MESSAGES, "");
textdomain("ldap-server");

use Digest::MD5 qw(md5_hex);
use Digest::SHA1 qw(sha1);
use MIME::Base64;
use X500::DN;

use YaPI;
@YaPI::LdapServer::ISA = qw( YaPI );

YaST::YCP::Import ("SCR");
YaST::YCP::Import ("Ldap");
YaST::YCP::Import ("Service");

our %TYPEINFO;
our @CAPABILITIES = (
                     'SLES9'
                    );

=item *
C<\@dbList = ReadDatabaseList()>

Returns a List of databases (suffix). 

EXAMPLE:

=cut

BEGIN { $TYPEINFO{ReadDatabaseList} = ["function", ["list", "string"]]; }
sub ReadDatabaseList {
    my $self = shift;
    
    my $dbList = SCR->Read( ".ldapserver.databaselist" );
    if(! defined $dbList) {
        return $self->SetError(%{SCR->Error(".ldapserver")}); 
    }
    return $dbList;
}

=item *
C<$bool = AddDatabase( \%valueMap )>

Creates a new database section in the configuration file,
start or restart the LDAP Server and add the base object.
If the database exists, nothing is done and undef is returned. 
Supported keys in %valueMap are:
 
 * database: The database type (required)
 
 * suffix: The suffix (required)
 
 * rootdn: The Root DN (required)
 
 * passwd: The plain Root Password (required)

 * cryptmethod: The crypt method; allowed values are (CRYPT, SMD5, SHA, SSHA, PLAIN); default is 'SSHA'
 
 * directory: The Directory where the database files are(bdb/ldbm) (required)
 
 * cachesize: The cachesize(bdb/ldbm) (optional; default 10000)
 
 * checkpoint: The checkpoint(bdb) (optional; default 1024 5)

EXAMPLE:

=cut

BEGIN { $TYPEINFO{AddDatabase} = ["function", "boolean", ["map", "string", "any"]]; }
sub AddDatabase {
    my $self = shift;
    my $data = shift;

    my $passwd_string = undef;
    my $cryptMethod   = "SSHA";
    my $cachesize     = undef;
    my $checkpoint    = undef;

    ################
    # check database
    ################
    if(!defined $data->{database} || $data->{database} eq "") {
                                          # error message at parameter check
        return $self->SetError(summary => "Missing parameter 'database'",
                               code => "PARAM_CHECK_FAILED");
    }
    if ( !grep( ($_ eq $data->{database}), ("bdb", "ldbm") ) ) {
        return $self->SetError(summary => sprintf(
                                   # error at paramter check
                                 _("Database type '%s' is not supported. Allowed are 'bdb' and 'ldbm'"),
                                                  $data->{database}),
                               code => "PARAM_CHECK_FAILED");
    }

    ################
    # check suffix
    ################
    if(!defined $data->{suffix} || $data->{suffix} eq "") {
        return $self->SetError(summary => "Missing parameter 'suffix'",
                               code => "PARAM_CHECK_FAILED");
    }

    my $object = X500::DN->ParseRFC2253($data->{suffix});
    my @attr = $object->getRDN($object->getRDNs()-1)->getAttributeTypes();
    my $val = $object->getRDN($object->getRDNs()-1)->getAttributeValue($attr[0]);
    
    if(!defined $attr[0] || !defined $val) {
        return $self->SetError(summary => "Can not parse 'suffix'",
                               description => "Parsing error for suffix '".$data->{suffix}."'",
                               code => "PARSE_ERROR");
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
                                   # parameter check failed
            return $self->SetError(summary => _("The countryName must be a ISO-3166 country 2-letter code"),
                                   description => "Invalid value for 'c' ($val)",
                                   code => "PARAM_CHECK_FAILED");
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
                  "objectClass" => [ "dcObject" ],
                  "dc" => $val,
                 }
    } else {
                               # parameter check failed
        return $self->SetError(summary => _("First part of suffix must be c=, st=, l=, o=, ou= or dc="),
                               code => "PARAM_CHECK_FAILED");
    }

    ##############
    # check rootdn
    ##############
    if(!defined $data->{rootdn} || $data->{rootdn} eq "") {
                               # parameter check failed
        return $self->SetError(summary => "Missing parameter 'rootdn'",
                               code => "PARAM_CHECK_FAILED");
    }

    if($data->{rootdn} !~ /$data->{suffix}$/) {
                               # parameter check failed
        return $self->SetError(summary => _("'rootdn' must be below the 'suffix'"),
                               code => "PARAM_CHECK_FAILED");
    }

    ##############################
    # check passwd and cryptmethod
    ##############################

    if(!defined $data->{passwd} || $data->{passwd} eq "") {
                               # parameter check failed
        return $self->SetError(summary => _("You must define 'passwd'"),
                               code => "PARAM_CHECK_FAILED");
    }
    if(!defined $data->{passwd} || $data->{passwd} eq "") {
                               # parameter check failed
        return $self->SetError(summary => _("You must define 'passwd'"),
                               code => "PARAM_CHECK_FAILED");
    }

    if(defined $data->{cryptmethod} && $data->{cryptmethod} ne "") {
        $cryptMethod = $data->{cryptmethod};
    }
    if( !grep( ($_ eq $cryptMethod), ("CRYPT", "SMD5", "SHA", "SSHA", "PLAIN") ) ) {
        return $self->SetError(summary => sprintf(
                               # parameter check failed
                                                  _("'%s' is an unsupported crypt method."),
                                                  $cryptMethod),
                               code => "PARAM_CHECK_FAILED");
    }

    if( $cryptMethod eq "CRYPT" ) {
        my $salt =  pack("C2",(int(rand 26)+65),(int(rand 26)+65));
        $passwd_string = crypt $data->{passwd},$salt;
        $passwd_string = "{crypt}".$passwd_string;
    } elsif( $cryptMethod eq "SMD5" ) {
        my $salt =  pack("C5",(int(rand 26)+65),(int(rand 26)+65),(int(rand 26)+65),
                         (int(rand 26)+65), (int(rand 26)+65));
        my $ctx = new Digest::MD5();
        $ctx->add($data->{passwd});
        $ctx->add($salt);
        $passwd_string = "{smd5}".encode_base64($ctx->digest.$salt, "");
    } elsif( $cryptMethod eq "SHA"){
        my $digest = sha1($data->{passwd});
        $passwd_string = "{sha}".encode_base64($digest, "");
    } elsif( $cryptMethod eq "SSHA"){
        my $salt =  pack("C5",(int(rand 26)+65),(int(rand 26)+65),(int(rand 26)+65),
                         (int(rand 26)+65), (int(rand 26)+65));
        my $digest = sha1($data->{passwd}.$salt);
        $passwd_string = "{ssha}".encode_base64($digest.$salt, "");
    } else {
        $passwd_string = $data->{passwd};
    }
    
    #################
    # check directory
    #################
    
    if(!defined $data->{directory} || $data->{directory} eq "") {
                               # parameter check failed
        return $self->SetError(summary => _("You must define 'directory'"),
                               code => "PARAM_CHECK_FAILED");
    }
    if( ! defined  SCR->Read(".target.dir", $data->{directory})) {
                               # parameter check failed
        return $self->SetError(summary => _("The directory does not exist."),
                               description => "The 'directory' (".$data->{directory}.") does not exist.",
                               code => "DIR_DOES_NOT_EXIST");
    }

    ##################
    # check cachesize
    ##################
    if(defined $data->{cachesize} && $data->{cachesize} ne "") {

        if($data->{cachesize} !~ /^\d+$/) {
            return $self->SetError(summary => _("Invalid cachesize value."),
                                   description => "cachesize = '".$data->{cachesize}."'. Must be a integer value",
                                   code => "PARAM_CHECK_FAILED");
        }
        $cachesize = $data->{cachesize};
    }
    if(! exists $data->{cachesize}) {
        # set default if parameter does not exist
        $cachesize = 10000;
    }
    
    if($data->{database} eq "bdb") {
        ##################
        # check checkpoint
        ##################
        if(defined $data->{checkpoint} && $data->{checkpoint} ne "") {
            my @cp = split(/\s+/, $data->{checkpoint});
            if(!defined $cp[0] || !defined $cp[1] ||
               $cp[0] !~ /^\d+$/ || $cp[1] !~ /^\d+$/) {
                return $self->SetError(summary => _("Invalid checkpoint value."),
                                       description => "checkpoint = '".$data->{checkpoint}."'.\n Must be two integer values seperated by space.",
                                       code => "PARAM_CHECK_FAILED");
            }
            $checkpoint = $cp[0]." ".$cp[1];
        }
        if(! exists $data->{checkpoint}) {
            # set default if parameter does not exist
            $checkpoint = "1024 5";
        }
    }




}

=item *
C<$bool = EditDatabase($suffix, \%valueMap )>

Edit the database section with the suffix B<$suffix> in the configuration file.
Only save parameter are supported. 
Supported keys in %valueMap are:
 
 * rootdn: The Root DN
 
 * passwd: The Root Password
 
 * cryptmethod: The crypt method; allowed values are (CRYPT, SMD5, SHA, SSHA, PLAIN); default is 'SSHA'

 * cachesize: The cachesize(bdb/ldbm)
 
 * checkpoint: The checkpoint(bdb)

If the key is defined, but the value is 'undef' the option will be deleted.
If a key is not defined, the option is not changed.
If the key is defined and a value is specified, this value will be set.

rootdn, passwd and cryptmethod can not be deleted.

EXAMPLE:

=cut

BEGIN { $TYPEINFO{EditDatabase} = ["function", "boolean", "string", ["map", "string", "any"]]; }
sub EditDatabase {
    my $self   = shift;
    my $suffix = shift;
    my $data   = shift;
    my $cryptMethod = undef;
    my $passwd_string = undef;
    
    if(!defined $suffix || $suffix eq "") {
        return $self->SetError(summary => "Missing parameter 'suffix'",
                               code => "PARAM_CHECK_FAILED");
    }

    ###################
    # work on rootdn
    ###################
    if(exists $data->{rootdn} && ! defined $data->{rootdn}) {
                               # parameter check failed
        return $self->SetError(summary => _("'rootdn' is required. You can not delete it"),
                               code => "PARAM_CHECK_FAILED");
    } elsif(exists $data->{rootdn}) {
        if($data->{rootdn} !~ /$suffix$/) {
            # parameter check failed
            return $self->SetError(summary => _("'rootdn' must be below the 'suffix'"),
                                   code => "PARAM_CHECK_FAILED");
        } else {
            # set new rootdn
            # FIXME: do it here
        }
    }

    ###################
    # work on passwd
    ###################
    if(exists $data->{passwd} && ! defined $data->{passwd}) {
                                           # parameter check failed
        return $self->SetError(summary => _("'passwd' is required. You can not delete it"),
                               code => "PARAM_CHECK_FAILED");
    } elsif(exists $data->{passwd}) {

        if(!defined $data->{passwd} || $data->{passwd} eq "") {
                                               # parameter check failed
            return $self->SetError(summary => _("You must define 'passwd'"),
                                   code => "PARAM_CHECK_FAILED");
        }
        if(!defined $data->{passwd} || $data->{passwd} eq "") {
                                   # parameter check failed
            return $self->SetError(summary => _("You must define 'passwd'"),
                                   code => "PARAM_CHECK_FAILED");
        }

        if(defined $data->{cryptmethod} && $data->{cryptmethod} ne "") {
            $cryptMethod = $data->{cryptmethod};
        }
        if( !grep( ($_ eq $cryptMethod), ("CRYPT", "SMD5", "SHA", "SSHA", "PLAIN") ) ) {
            return $self->SetError(summary => sprintf(
                                                      # parameter check failed
                                                      _("'%s' is an unsupported crypt method."),
                                                      $cryptMethod),
                                   code => "PARAM_CHECK_FAILED");
        }

        if( $cryptMethod eq "CRYPT" ) {
            my $salt =  pack("C2",(int(rand 26)+65),(int(rand 26)+65));
            $passwd_string = crypt $data->{passwd},$salt;
            $passwd_string = "{crypt}".$passwd_string;
        } elsif( $cryptMethod eq "SMD5" ) {
            my $salt =  pack("C5",(int(rand 26)+65),(int(rand 26)+65),(int(rand 26)+65),
                             (int(rand 26)+65), (int(rand 26)+65));
            my $ctx = new Digest::MD5();
            $ctx->add($data->{passwd});
            $ctx->add($salt);
            $passwd_string = "{smd5}".encode_base64($ctx->digest.$salt, "");
        } elsif( $cryptMethod eq "SHA"){
            my $digest = sha1($data->{passwd});
            $passwd_string = "{sha}".encode_base64($digest, "");
        } elsif( $cryptMethod eq "SSHA"){
            my $salt =  pack("C5",(int(rand 26)+65),(int(rand 26)+65),(int(rand 26)+65),
                             (int(rand 26)+65), (int(rand 26)+65));
            my $digest = sha1($data->{passwd}.$salt);
            $passwd_string = "{ssha}".encode_base64($digest.$salt, "");
        } else {
            $passwd_string = $data->{passwd};
        }
        # set new rootdn
        # FIXME: do it here
    }

    ###################
    # work on cachesize
    ###################
    if(exists $data->{cachesize} && !defined $data->{cachesize}) {
        # Delete cachesize option
        # FIXME: do it here
    } elsif(exists $data->{cachesize}) {

        if(defined $data->{cachesize} && $data->{cachesize} ne "") {

            if($data->{cachesize} !~ /^\d+$/) {
                return $self->SetError(summary => _("Invalid cachesize value."),
                                       description => "cachesize = '".$data->{cachesize}."'. Must be a integer value",
                                       code => "PARAM_CHECK_FAILED");
            }
            #$cachesize = $data->{cachesize};
            # set new cachesize
            # FIXME: do it here
        } else {
            return $self->SetError(summary => _("Invalid cachesize value."),
                                   description => "cachesize = '".$data->{cachesize}."'. Must be a integer value",
                                   code => "PARAM_CHECK_FAILED");
        }
    }

    ####################
    # work on checkpoint
    ####################
    if(exists $data->{checkpoint}) {

        if(!defined $data->{checkpoint}) {
            # Delete checkpoint option
            # FIXME: do it here
        } else {

            my $db = $self->ReadDatabase($suffix);
            return undef if(! defined $db);
            
            if($db->{database} eq "bdb") {

                if($data->{checkpoint} ne "") {
                    my @cp = split(/\s+/, $data->{checkpoint});
                    if(!defined $cp[0] || !defined $cp[1] ||
                       $cp[0] !~ /^\d+$/ || $cp[1] !~ /^\d+$/) {
                        return $self->SetError(summary => _("Invalid checkpoint value."),
                                               description => "checkpoint = '".$data->{checkpoint}."'.\n Must be two integer values seperated by space.",
                                               code => "PARAM_CHECK_FAILED");
                    }
                    #$checkpoint = $cp[0]." ".$cp[1];
                    # set new checkpoint
                    # FIXME: do it here
                } else {
                    return $self->SetError(summary => _("Invalid checkpoint value."),
                                           description => "checkpoint = '".$data->{checkpoint}."'.\n Must be two integer values seperated by space.",
                                           code => "PARAM_CHECK_FAILED");
                }
            }
        }
    }
    return 1;
}

=item *
C<$valueMap = ReadDatabase( $suffix )>

Read the database section with the suffix B<$suffix>. 
Supported keys in %valueMap are:
 
 * database: The database type
 
 * suffix: The suffix
 
 * rootdn: The Root DN
 
 * passwd: The Root Password
 
 * directory: The Directory where the database files are(bdb/ldbm)
 
 * cachesize: The cachesize(bdb/ldbm)
 
 * checkpoint: The checkpoint(bdb)
 

EXAMPLE:

=cut

BEGIN { $TYPEINFO{ReadDatabase} = ["function", ["map", "string", "any"], "string"]; }
sub ReadDatabase {
    my $self = shift;
    my $suffix = shift;

    if(! defined $suffix || $suffix eq "") {
                                          # error message at parameter check
        return $self->SetError(summary => _("Missing Parameter 'suffix'."),
                               code => "PARAM_CHECK_FAILED");
    }
    my $dbHash = SCR->Read( ".ldapserver.database", $suffix );
    if(! defined $dbHash) {
        return $self->SetError(%{SCR->Error(".ldapserver")});
    }
    if(exists $dbHash->{index}) {
        # we have a special function to maintain 'index'
        delete $dbHash->{index};
    }
    return $dbHash;
}

=item *
C<\%indexMap = ReadIndex( $suffix )>

Returns a Map with all index statements for this database. The "key" is the md5sum 
of the statement, the "value" is the statement itself.

EXAMPLE:

=cut

BEGIN { $TYPEINFO{ReadIndex} = ["function", ["map", "string", "string"], "string"]; }
sub ReadIndex {
    my $self = shift;
    my $suffix = shift;
    my $idxHash = {};

    if(! defined $suffix || $suffix eq "") {
                                          # error message at parameter check
        return $self->SetError(summary => _("Missing Parameter 'suffix'."),
                               code => "PARAM_CHECK_FAILED");
    }
    my $dbHash = SCR->Read( ".ldapserver.database", $suffix );
    if(! defined $dbHash) {
        return $self->SetError(%{SCR->Error(".ldapserver")});
    }
    if(exists $dbHash->{index} && defined $dbHash->{index} &&
       ref $dbHash->{index} eq "ARRAY") {
        
        foreach my $idx (@{$dbHash->{index}}) {
            my $hex = md5_hex($idx);
            $idxHash->{"$hex"} = $idx;
        }
        
    }
    return $idxHash;
}

=item *
C<$bool = AddIndex( $suffix, $index )>

Add a new index statement B<$index> to the database section B<$suffix>.

EXAMPLE:

=cut

BEGIN { $TYPEINFO{AddIndex} = ["function", "boolean", "string", "string"]; }
sub AddIndex {
    my $self = shift;
    

}

=item *
C<$bool = EditIndex( $suffix, $index_md5, $index )>

Replace the index B<$index_md5> in the database section B<$suffix> by the new index
statement B<$index>.

EXAMPLE:

=cut

BEGIN { $TYPEINFO{EditIndex} = ["function", "boolean", "string", "string", "string"]; }
sub EditIndex {
    my $self = shift;
    

}

=item *
C<$bool = DeleteIndex( $suffix, $index_md5 )>

Delete the index B<$index_md5> statement in the database section B<$suffix>. 

EXAMPLE:

=cut

BEGIN { $TYPEINFO{DeleteIndex} = ["function", "boolean", "string", "string" ]; }
sub DeleteIndex {
    my $self = shift;
    

}

=item *
C<$bool = RecreateIndex( $suffix )>

Regenerate indices based upon the current contents of a 
database determined by $suffix. This function stops the 
ldapserver, call slapindex and start the ldapserver again.

EXAMPLE:

=cut

BEGIN { $TYPEINFO{RecreateIndex} = ["function", "boolean", "string" ]; }
sub RecreateIndex {
    my $self = shift;
    
    
}

=item *
C<\@list = ReadSchemaIncludeList()>

Returns a list of all included schema files in the order they appear in the config files.

EXAMPLE:

=cut

BEGIN { $TYPEINFO{ReadSchemaIncludeList} = ["function", ["list", "string"] ]; }
sub ReadSchemaIncludeList {
    my $self = shift;

    my $global = SCR->Read( ".ldapserver.global" );
    if(! defined $global) {
        return $self->SetError(%{SCR->Error(".ldapserver")});
    }
    if(exists $global->{schemainclude} && defined $global->{schemainclude} &&
       ref $global->{schemainclude} eq "ARRAY") {
        return $global->{schemainclude};
    }
    return ();
}

=item *
C<$bool = WriteSchemaIncludeList( \@list )>

Writes all schema includes preserving order.

EXAMPLE:

=cut

BEGIN { $TYPEINFO{WriteSchemaIncludeList} = ["function", "boolean", ["list", "string"] ]; }
sub WriteSchemaIncludeList {
    my $self = shift;
    
                                    
}

=item *
C<\@list = ReadAllowList()>

Returns a list of allow statements. 

EXAMPLE:

=cut

BEGIN { $TYPEINFO{ReadAllowList} = ["function", ["list", "string"] ]; }
sub ReadAllowList {
    my $self = shift;
    my @allowList = ();

    my $global = SCR->Read( ".ldapserver.global" );
    if(! defined $global) {
        return $self->SetError(%{SCR->Error(".ldapserver")});
    }
    if(exists $global->{allow} && defined $global->{allow} &&
       ref $global->{allow} eq "ARRAY") {
        
        foreach my $a (@{$global->{allow}}) {
            next if( $a eq "");
            my @al = split(/\s+/, $a);
            foreach my $value ( @al ) {
                $value =~ s/\s+/ /sg;
                $value =~ s/\s+$//;
                next if( $value eq "");
                push @allowList, $value;
            }
        }
    }
    return \@allowList;
}

=item *
C<$bool = AddAllow( $feature_string )>

Adds an allow feature; if the specified feature is already activated, nothing happens.

EXAMPLE:

=cut

BEGIN { $TYPEINFO{AddAllow} = ["function", "boolean", "string" ]; }
sub AddAllow {
    my $self = shift;
}

=item *
C<$bool = DeleteAllow( $feature_string )>

Removes a specific allow feature. 

EXAMPLE:

=cut

BEGIN { $TYPEINFO{DeleteAllow} = ["function", "boolean", "string" ]; }
sub DeleteAllow {
    my $self = shift;
    

}

=item *
C<$bool = WriteAllowList( \@list ) >

Replaces the complete allow option with the specified feature list.

EXAMPLE:

=cut

BEGIN { $TYPEINFO{WriteAllowList} = ["function", "boolean", [ "list", "string"] ]; }
sub WriteAllowList {
    my $self = shift;
    

}

=item *
C<$loglevel = ReadLoglevel()>

Read the loglevel bitmask.

EXAMPLE:

=cut

BEGIN { $TYPEINFO{ReadLoglevel} = ["function", "integer" ]; }
sub ReadLoglevel {
    my $self = shift;
    my $loglevel = 0;

    my $global = SCR->Read( ".ldapserver.global" );
    if(! defined $global) {
        return $self->SetError(%{SCR->Error(".ldapserver")});
    }
    if(exists $global->{loglevel} && defined $global->{loglevel}) {
        
        $loglevel = $global->{loglevel};
        
    }
    return $loglevel;
}

=item *
C<$bool = AddLoglevel( $bit )>

Adds a loglevel bit to the current bitmask.

EXAMPLE:

=cut

BEGIN { $TYPEINFO{AddLoglevel} = ["function", "boolean", "integer" ]; }
sub AddLoglevel {
    my $self = shift;
    

}

=item *
C<$bool = DeleteLoglevel( $bit )>

Removes a loglevel bit from the bitmask.

EXAMPLE:

=cut

BEGIN { $TYPEINFO{DeleteLoglevel} = ["function", "boolean", "integer" ]; }
sub DeleteLoglevel {
    my $self = shift;
    

}

=item *
C<$bool = WriteLoglevel( $loglevel )>

Replaces the loglevel bitmask. 

EXAMPLE:

=cut

BEGIN { $TYPEINFO{WriteLoglevel} = ["function", "boolean", "integer" ]; }
sub WriteLoglevel {
    my $self = shift;
    

}

=item *
C<ModifyService($status)>

with this function you can turn on and off the LDAP server
runlevel script.
Turning off means, no LDAP server start at boot time.

EXAMPLE

 ModifyService(0); # turn LDAP server off at boot time
 ModifyService(1); # turn LDAP server on at boot time

=cut

BEGIN { $TYPEINFO{ModifyService} = ["function", "boolean", "boolean" ]; }
sub ModifyService {
    my $self = shift;
    my $enable = shift;

    if( $enable ) {
        Service->Adjust( "ldap", "enable" );
    } else {
        Service->Adjust( "ldap", "disable" );
    }
    return 1;
}

=item *
C<SwitchService($status)>

with this function you can start and stop the LDAP server
service.

EXAMPLE

 SwitchService( 0 ); # turning off the LDAP server service
 SwitchService( 1 ); # turning on the LDAP server service

=cut

sub SwitchService {
    my $self = shift;
    my $enable = shift;

    if( $enable ) {
        Service->RunInitScript( "ldap", "restart");
    } else {
        Service->RunInitScript( "ldap", "stop" );
    }
}

=item *
C<$status = ReadService()>

with this function you can read out the state of the
LDAP server runlevel script (starting LDAP server at boot time).

EXAMPLE

 print "LDAP is ".( (ReadService())?('on'):('off') )."\n";

=cut
BEGIN { $TYPEINFO{ReadService} = ["function", "boolean"]; }
sub ReadService {
    my $self = shift;
    return Service->Enabled('ldap');
}
