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

use YaPI;
@YaPI::LdapServer::ISA = qw( YaPI );

YaST::YCP::Import ("SCR");
YaST::YCP::Import ("Ldap");

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

Creates a new database section in the configuration file. 
If the database exists, nothing is done and undef is returned. 
Supported keys in %valueMap are:
 
 * database: The database type
 
 * suffix: The suffix
 
 * rootdn: The Root DN
 
 * rootpw: The Root Password
 
 * directory: The Directory where the database files are(bdb/ldbm)
 
 * cachesize: The cachesize(bdb/ldbm)
 
 * checkpoint: The checkpoint(bdb)

EXAMPLE:

=cut

BEGIN { $TYPEINFO{AddDatabase} = ["function", "boolean", ["map", "string", "any"]]; }
sub AddDatabase {
    my $self = shift;
    

}

=item *
C<$bool = EditDatabase($suffix, \%valueMap )>

Edit the database section with the suffix B<$suffix> in the configuration file.
Only save parameter are supported. 
Supported keys in %valueMap are:
 
 * rootdn: The Root DN
 
 * rootpw: The Root Password
 
 * cachesize: The cachesize(bdb/ldbm)
 
 * checkpoint: The checkpoint(bdb)

EXAMPLE:

=cut

BEGIN { $TYPEINFO{EditDatabase} = ["function", "boolean", "string", ["map", "string", "any"]]; }
sub EditDatabase {
    my $self = shift;
    

}

=item *
C<$valueMap = ReadDatabase( $suffix )>

Read the database section with the suffix B<$suffix>. 
Supported keys in %valueMap are:
 
 * database: The database type
 
 * suffix: The suffix
 
 * rootdn: The Root DN
 
 * rootpw: The Root Password
 
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
    my @incList = ();

    my $global = SCR->Read( ".ldapserver.global" );
    if(! defined $global) {
        return $self->SetError(%{SCR->Error(".ldapserver")});
    }
    use Data::Dumper;
    print Data::Dumper->Dump([$global])."\n";
    if(exists $global->{include} && defined $global->{include} &&
       ref $global->{include} eq "ARRAY") {
        foreach my $inc (@{$global->{include}}) {
            next if( $inc eq "");
            if( $inc =~ /schema$/ ) {
                push @incList, $inc;
            }
        }
    }
    return \@incList;
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









