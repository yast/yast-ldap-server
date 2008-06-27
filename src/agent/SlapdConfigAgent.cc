#include "SlapdConfigAgent.h"
#include <LDAPConnection.h>
#include <LDAPException.h>
#include <LdifReader.h>
#include <LdifWriter.h>
#include <LDAPEntry.h>
#include <sstream>

#define DEFAULT_PORT 389
#define ANSWER	42
#define MAX_LENGTH_ID 5

SlapdConfigAgent::SlapdConfigAgent()
{
    y2milestone("SlapdConfigAgent::SlapdConfigAgent");
//    LDAPConnection *lc = new LDAPConnection("ldap://localhost");
//    lc->bind("cn=config", "secret");
//    olc = OlcConfig(lc);
}

SlapdConfigAgent::~SlapdConfigAgent()
{}

YCPValue SlapdConfigAgent::Read( const YCPPath &path,
                                 const YCPValue &arg,
                                 const YCPValue &opt)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    y2milestone("Component %s ", path->component_str(0).c_str());

    if ( path->length() < 1 ) {
        return YCPNull();
    } 
    else if ( path->component_str(0) == "global" ) 
    {
        y2milestone("Global read");
        return ReadGlobal(path->at(1), arg, opt);
    } 
    else if ( path->component_str(0) == "databases" ) 
    {
        y2milestone("read databases");
        return ReadDatabases(path->at(1), arg, opt);
    }
    else if ( path->component_str(0) == "configAsLdif" )
    {
        return ConfigToLdif();
    }
    return YCPNull();
}


YCPBoolean SlapdConfigAgent::Write( const YCPPath &path,
                                  const YCPValue &arg,
                                  const YCPValue &arg2)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());

    if ( path->length() < 2 ) {
        return YCPNull();
    } else if ( path->component_str(0) == "global" ) {
        y2milestone("Global Write");
        return WriteGlobal(path->at(1), arg, arg2);
    } else {
        return YCPNull();
    }
}

YCPValue SlapdConfigAgent::Execute( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &arg2)
{
    y2milestone("Execute Path %s", path->toString().c_str() );
    if ( path->component_str(0) == "initFromLdif" )
    {
        std::istringstream ldifstream(arg->asString()->value_cstr());
        LdifReader ldif(ldifstream);
        while ( ldif.readNextRecord() )
        {   
            LDAPEntry currentEntry = ldif.getEntryRecord();
            y2milestone( "EntryDN: %s", ldif.getEntryRecord().getDN().c_str() );
            StringList oc = currentEntry.getAttributeByName("objectclass")->getValues();
            string ocstring;
            for( StringList::const_iterator i = oc.begin(); i != oc.end(); i++ )
            {
                ocstring += *i;
                ocstring += " ";
            }
            y2milestone( "objectclasses: %s", ocstring.c_str());
            y2milestone( "isDatabase: %i", OlcConfigEntry::isDatabaseEntry(currentEntry) );
            if (OlcConfigEntry::isDatabaseEntry(currentEntry) )
            {
                boost::shared_ptr<OlcDatabase> olce(OlcDatabase::createFromLdapEntry(currentEntry));
                databases.push_back(olce);
            }
            else if (OlcConfigEntry::isGlobalEntry(currentEntry) )
            {
                globals = boost::shared_ptr<OlcGlobalConfig>(new OlcGlobalConfig(currentEntry));
            }
        }
    }
    else if ( path->component_str(0) == "initGlobals" )
    {
        globals = boost::shared_ptr<OlcGlobalConfig>(new OlcGlobalConfig());
        globals->setStringValue("olcPidFile", "/var/run/slapd/slapd.pid");
        globals->setStringValue("olcArgsFile", "/var/run/slapd/slapd.args");
        globals->setStringValue("olcAuthzRegexp", 
                "gidNumber=0\\+uidNumber=0,cn=peercred,cn=external,cn=auth dn:cn=config");
    }
    else if ( path->component_str(0) == "initSchema" )
    {   
        schemaBase = boost::shared_ptr<OlcSchemaConfig>(new OlcSchemaConfig() );
        YCPList schemaList = arg->asList();
        for ( int i = 0; i < schemaList->size(); i++ )
        {
            y2milestone("Schemafile to include: %s", schemaList->value(i)->asString()->value_cstr() );
        }

    }
    else if ( path->component_str(0) == "initDatabases" )
    {
        YCPList dbList = arg->asList();
        for ( int i = 0; i < dbList->size(); i++ )
        {
            YCPMap dbMap = dbList->value(i)->asMap();
            std::string dbtype(dbMap->value(YCPString("type"))->asString()->value_cstr());
            y2milestone("Database Type: %s", dbtype.c_str());
            if ( dbtype == "bdb" )
            {
                boost::shared_ptr<OlcBdbDatabase> db(new OlcBdbDatabase() );
                db->setIndex(i);
                db->setSuffix(dbMap->value(YCPString("suffix"))->asString()->value_cstr());
                db->setRootDn(dbMap->value(YCPString("rootdn"))->asString()->value_cstr());
                db->setDirectory(dbMap->value(YCPString("directory"))->asString()->value_cstr());
//                db->setRootPw(dbMap->value(YCPString("rootpw"))->asString()->toString());
                databases.push_back(db);
            }
            else
            {
                y2error("Database Type \"%s\" not supported. Trying to use generic Database class", dbtype.c_str());
                boost::shared_ptr<OlcDatabase> db(new OlcDatabase(dbtype.c_str()) );
                db->setIndex(i);
//                db->setSuffix(dbMap->value(YCPString("suffix"))->asString()->value_cstr());
                db->setRootDn(dbMap->value(YCPString("rootdn"))->asString()->value_cstr());
                db->setRootPw(dbMap->value(YCPString("rootpw"))->asString()->value_cstr());
                databases.push_back(db);
            }
        }
    }
    return YCPBoolean(true);
}

YCPList SlapdConfigAgent::Dir( const YCPPath &path)
{
    return YCPNull();
}

YCPValue SlapdConfigAgent::otherCommand( const YCPTerm& term)
{
    y2milestone("SlapdConfigAgent::otherCommand -> %s ", term->name().c_str());
    std::string sym = term->name();

    if (sym == "SlapdConfigAgent") {
        /* Your initialization */
        return YCPVoid();
    }

    return YCPNull();

}

YCPValue SlapdConfigAgent::ReadGlobal( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &opt)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    y2milestone("Component: %s", path->component_str(0).c_str());
    if ( path->length() == 0 ) 
    {
        return YCPNull();
    } 
    else
    {
        if ( path->component_str(0) == "loglevel" )
        {
            y2milestone("Read loglevel");
            YCPList yLevelList;
            const std::vector<std::string> loglevel = globals->getLogLevelString();
            std::vector<std::string>::const_iterator i;
            for ( i = loglevel.begin(); i != loglevel.end(); i++ )
            {
                yLevelList.add(YCPString(*i) );
            }
            return yLevelList;
        }
        if ( path->component_str(0) == "tlsSettings" )
        {
            YCPMap ymap;
            const OlcTlsSettings tls( globals->getTlsSettings() );
            ymap.add(YCPString("crlCheck"), YCPInteger( tls.getCrlCheck() ) );
            ymap.add(YCPString("verifyClient"), YCPInteger( tls.getVerifyClient() ) );
            return ymap;
        }
    }
    return YCPNull();
}

YCPValue SlapdConfigAgent::ReadDatabases( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &opt)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    std::list<boost::shared_ptr<OlcDatabase> >::const_iterator i;
    YCPList dbList;
    for (i = databases.begin(); i != databases.end(); i++ )
    {
        YCPMap ymap;
        std::map<std::string, std::list<std::string> > dbMap = (*i)->toMap();
        std::map<std::string, std::list<std::string> >::const_iterator j;
        for ( j = dbMap.begin(); j != dbMap.end(); j++ )
        {
            YCPList l;
            YCPString type(j->first);
            std::list<std::string> vals = j->second;
            std::list<std::string>::const_iterator k;
            for (k = vals.begin(); k != vals.end(); k++ )
            {
                l.add(YCPString(*k));
            }
            ymap.add(type, l);
        }
        dbList.add(ymap);
    }
    return dbList;
}

YCPBoolean SlapdConfigAgent::WriteGlobal( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &arg2)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    y2milestone("Component: %s", path->component_str(0).c_str());
    if ( path->length() == 0 ) {
        return YCPNull();
    } else {
        if ( path->component_str(0) == "loglevel" ) {
            y2milestone("Write loglevel");
            YCPList levels = arg->asList();
            std::list<std::string> levelList;
            for ( int i = 0; i < levels->size(); i++ )
            {
                levelList.push_back( levels->value(i)->asString()->value_cstr() );
            }
            globals->setLogLevel( levelList );
            //olc.setGlobals(olcg);
            return YCPBoolean(true);
        }
    }
    return YCPBoolean(false);
}

YCPString SlapdConfigAgent::ConfigToLdif() const
{
    y2milestone("ConfigToLdif");
    std::list<boost::shared_ptr<OlcDatabase> >::const_iterator i = databases.begin();
    std::ostringstream ldif;
    ldif << globals->toLdif() << std::endl;
    ldif << schemaBase->toLdif() << std::endl;
    LdifWriter writer(ldif);
    writer.writeIncludeRecord("/etc/openldap/schema/core.ldif");
    writer.writeIncludeRecord("/etc/openldap/schema/cosine.ldif");
    writer.writeIncludeRecord("/etc/openldap/schema/inetorgperson.ldif");
    ldif << std::endl;
    for ( ; i != databases.end(); i++ )
    {
        ldif << (*i)->toLdif() << std::endl;
    }
    return YCPString(ldif.str());
}
