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
