#! /usr/bin/perl -w 

BEGIN {
    push @INC, '/usr/share/YaST2/modules/';
}

use strict;
use YaST::YCP;
use ycp;
use Data::Dumper;
use YaPI::LdapServer;

my $pwd = $ENV{'PWD'};
print "$pwd\n";
exit 1 if (!defined $pwd || $pwd eq "");

init_testsetup();
T01_Interface();
T02_Version();
T03_Capabilities();
T04_ReadDatabaseList();
T05_ReadDatabase();
T06_ReadIndex();
T07_ReadSchemaIncludeList();
T08_ReadAllowList();
T09_AddDatabase();
T10_EditDatabase();
T11_AddIndex();
T12_EditIndex();
T13_DeleteIndex();
T14_RecreateIndex();
T15_WriteSchemaIncludeList();
T16_WriteAllowList();

sub printError {
    my $err = shift;
    foreach my $k (keys %$err) {
        print STDERR "$k = ".$err->{$k}."\n";
    }
    print STDERR "\n";
    exit 1;
}

sub init_testsetup {

    if( -d "/$pwd/testout") {
        system("rm -r /$pwd/testout");
    }
    mkdir("/$pwd/testout", 0755);
    open(STDERR, ">> /$pwd/testout/YaST2-LdapServer-fulltest-OUTPUT.log");
}

sub T01_Interface {

    print STDERR "------------------- T01_Interface ---------------------\n";
    print "------------------- T01_Interface ---------------------\n";
    my $res = YaPI::LdapServer->Interface();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump($res)."\n";
    }
}

sub T02_Version {
    print STDERR "------------------- T02_Version ---------------------\n";
    print "------------------- T02_Version ---------------------\n";
    my $res = YaPI::LdapServer->Version();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T03_Capabilities {
    print STDERR "------------------- T03_Capabilities ---------------------\n";
    print "------------------- T03_Capabilities ---------------------\n";
    foreach my $cap ("SLES9", "USER") {
        my $res = YaPI::LdapServer->Supports($cap);
        if( not defined $res ) {
            my $msg = YaPI::LdapServer->Error();
            printError($msg);
        } else {
            print "OK: test CAP = $cap\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub T04_ReadDatabaseList {
    print STDERR "------------------- T04_ReadDatabaseList ---------------------\n";
    print "------------------- T04_ReadDatabaseList ---------------------\n";

    my $res = YaPI::LdapServer->ReadDatabaseList();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T05_ReadDatabase {
    print STDERR "------------------- T05_ReadDatabase ---------------------\n";
    print "------------------- T05_ReadDatabase ---------------------\n";

    my $res = YaPI::LdapServer->ReadDatabase('"dc=suse,dc=de"');
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T06_ReadIndex {
    print STDERR "------------------- T06_ReadIndex ---------------------\n";
    print "------------------- T06_ReadIndex ---------------------\n";

    my $res = YaPI::LdapServer->ReadIndex('"dc=suse,dc=de"');
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T07_ReadSchemaIncludeList {
    print STDERR "------------------- T07_ReadSchemaIncludeList ---------------------\n";
    print "------------------- T07_ReadSchemaIncludeList ---------------------\n";

    my $res = YaPI::LdapServer->ReadSchemaIncludeList();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T08_ReadAllowList {
    print STDERR "------------------- T08_ReadAllowList ---------------------\n";
    print "------------------- T08_ReadAllowList ---------------------\n";

    my $res = YaPI::LdapServer->ReadAllowList();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T09_AddDatabase {
    print STDERR "------------------- T09_AddDatabase ---------------------\n";
    print "------------------- T09_AddDatabase ---------------------\n";

    my $hash = {
                database    => 'bdb',
                suffix      => 'dc=example,dc=com',
                rootdn      => "cn=Admin,dc=example,dc=com",
                passwd      => "system",
                cryptmethod => 'SMD5',
                directory   => "/var/lib/ldap/db3",
               };

    my $res = YaPI::LdapServer->AddDatabase($hash);
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T10_EditDatabase {
    print STDERR "------------------- T10_EditDatabase ---------------------\n";
    print "------------------- T10_EditDatabase ---------------------\n";

    my $hash = { suffix  => "dc=example,dc=com",
                 rootdn  => "cn=Administrator,dc=example,dc=com",
               };

    my $res = YaPI::LdapServer->EditDatabase($hash);
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }

    $hash = { suffix  => "dc=example,dc=com",
              rootpw  => "tralla",
              cryptmethod => "CRYPT"
            };

    my $res = YaPI::LdapServer->EditDatabase($hash);
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }

    $hash = { suffix  => "dc=example,dc=com",
              cachesize  => "20000",
            };

    my $res = YaPI::LdapServer->EditDatabase($hash);
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }

    $hash = { suffix  => "dc=example,dc=com",
              checkpoint  => "2048 10",
            };
    
    my $res = YaPI::LdapServer->EditDatabase($hash);
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T11_AddIndex {
    print STDERR "------------------- T11_AddIndex ---------------------\n";
    print "------------------- T11_AddIndex ---------------------\n";

    my $res = YaPI::LdapServer->AddIndex("dc=example,dc=com", "uid,cn eq");
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T12_EditIndex {
    print STDERR "------------------- T12_EditIndex ---------------------\n";
    print "------------------- T12_EditIndex ---------------------\n";

    my $res = YaPI::LdapServer->EditIndex("dc=example,dc=com", "eacc11456b6c2ae4e1aef0fa287e02b0",
                                          "uid,cn,gidnumber eq");
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T13_DeleteIndex {
    print STDERR "------------------- T13_DeleteIndex ---------------------\n";
    print "------------------- T13_DeleteIndex ---------------------\n";
    
    my $res = YaPI::LdapServer->DeleteIndex("dc=example,dc=com", "338a980b4eebe87365a4077067ce1559");
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T14_RecreateIndex {
    print STDERR "------------------- T14_RecreateIndex ---------------------\n";
    print "------------------- T14_RecreateIndex ---------------------\n";

    my $res = YaPI::LdapServer->RecreateIndex("dc=example,dc=com");
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T15_WriteSchemaIncludeList {
    print STDERR "------------------- T15_WriteSchemaIncludeList ---------------------\n";
    print "------------------- T15_WriteSchemaIncludeList ---------------------\n";

    my $schemas = {
                   '/etc/openldap/schema/core.schema',
                   '/etc/openldap/schema/cosine.schema',
                   '/etc/openldap/schema/inetorgperson.schema',
                   '/etc/openldap/schema/rfc2307bis.schema',
                   '/etc/openldap/schema/yast2userconfig.schema',
                   '/etc/openldap/schema/samba3.schema'
                  };

    my $res = YaPI::LdapServer->WriteSchemaIncludeList($schemas);
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T16_WriteAllowList {
    print STDERR "------------------- T16_WriteAllowList ---------------------\n";
    print "------------------- T16_WriteAllowList ---------------------\n";
    
    my @list = ();
    
    my $res = YaPI::LdapServer->WriteAllowList( \@list );
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }

    push @list, "bind_v2";

    my $res = YaPI::LdapServer->WriteAllowList( \@list );
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}
