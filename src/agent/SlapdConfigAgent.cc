#include "SlapdConfigAgent.h"
#include <LDAPConnection.h>
#include <LDAPException.h>
#include <LdifReader.h>
#include <LdifWriter.h>
#include <LDAPEntry.h>
#include <SaslInteraction.h>
#include <sstream>
#include <fstream>

#define DEFAULT_PORT 389
#define ANSWER	42
#define MAX_LENGTH_ID 5

class SaslExternalHandler : SaslInteractionHandler 
{
    public:
        virtual void handleInteractions(const std::list<SaslInteraction*> &cb );
        virtual ~SaslExternalHandler();
    private:
        std::list<SaslInteraction*> cleanupList;

};

void SaslExternalHandler::handleInteractions( const std::list<SaslInteraction *> &cb )
{
    std::list<SaslInteraction*>::const_iterator i;

    for (i = cb.begin(); i != cb.end(); i++ ) {
        cleanupList.push_back(*i);
    }
}

SaslExternalHandler::~SaslExternalHandler()
{
    std::list<SaslInteraction*>::const_iterator i;
    for (i = cleanupList.begin(); i != cleanupList.end(); i++ ) {
        delete(*i);
    }
}


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
    else if ( path->component_str(0) == "schemaList" )
    {
        y2milestone("read schemalist");
        return ReadSchemaList(path->at(1), arg, opt);
    }
    else if ( path->component_str(0) == "schema" )
    {
        return ReadSchema( path->at(1), arg, opt );
    }
    else if ( path->component_str(0) == "database" ) 
    {
        y2milestone("read database");
        return ReadDatabase(path->at(1), arg, opt);
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
    } else if ( path->component_str(0) == "database" ) {
        y2milestone("Database Write");
        return WriteDatabase(path->at(1), arg, arg2);
    } else if ( path->component_str(0) == "schema" ) {
        y2milestone("Schema Write");
        return WriteSchema(path->at(1), arg, arg2);
    } else {
        return YCPNull();
    }
}

YCPValue SlapdConfigAgent::Execute( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &arg2)
{
    y2milestone("Execute Path %s", path->toString().c_str() );
    if ( path->component_str(0) == "init" )
    {

        LDAPConnection *lc = new LDAPConnection("ldapi:///");
        SaslExternalHandler sih;
        lc->saslInteractiveBind("external", 2 /* LDAP_SASL_QUIET */, (SaslInteractionHandler*)&sih);
        olc = OlcConfig(lc); 
    }
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
    else if ( path->component_str(0) == "commitChanges" )
    {
        if ( globals )
            olc.updateEntry( *globals );

        OlcDatabaseList::const_iterator i;
        for ( i = databases.begin(); i != databases.end() ; i++ )
        {
            olc.updateEntry(**i);
        }
        OlcSchemaList::const_iterator j;
        for ( j = schema.begin(); j != schema.end() ; j++ )
        {
            olc.updateEntry(**j);
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
        if ( globals == 0 )
        {
            globals = olc.getGlobals();
        }
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
        if ( path->component_str(0) == "allow" )
        {
            y2milestone("Read allow Features");
            YCPList yFeatureList;
            const std::vector<std::string> loglevel = globals->getAllowFeatures();
            std::vector<std::string>::const_iterator i;
            for ( i = loglevel.begin(); i != loglevel.end(); i++ )
            {
                yFeatureList.add(YCPString(*i) );
            }
            return yFeatureList;
        }
        if ( path->component_str(0) == "disallow" )
        {
            y2milestone("Read allow Features");
            YCPList yFeatureList;
            const std::vector<std::string> loglevel = globals->getDisallowFeatures();
            std::vector<std::string>::const_iterator i;
            for ( i = loglevel.begin(); i != loglevel.end(); i++ )
            {
                yFeatureList.add(YCPString(*i) );
            }
            return yFeatureList;
        }
        if ( path->component_str(0) == "tlsSettings" )
        {
            YCPMap ymap;
            const OlcTlsSettings tls( globals->getTlsSettings() );
            ymap.add(YCPString("crlCheck"), YCPInteger( tls.getCrlCheck() ) );
            ymap.add(YCPString("verifyClient"), YCPInteger( tls.getVerifyClient() ) );
            ymap.add(YCPString("caCertDir"), YCPString( tls.getCaCertDir() ) );
            ymap.add(YCPString("caCertFile"), YCPString( tls.getCaCertFile() ) );
            ymap.add(YCPString("certFile"), YCPString( tls.getCertFile() ) );
            ymap.add(YCPString("certKeyFile"), YCPString( tls.getCertKeyFile() ) );
            ymap.add(YCPString("crlFile"), YCPString( tls.getCrlFile() ) );
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
    if ( databases.size() == 0 )
    {
        databases = olc.getDatabases();
    }
    OlcDatabaseList::const_iterator i;
    YCPList dbList;
    for (i = databases.begin(); i != databases.end(); i++ )
    {
        YCPMap ymap;
        ymap.add( YCPString("suffix"), YCPString((*i)->getSuffix()) );
        ymap.add( YCPString("type"), YCPString((*i)->getType()) );
        ymap.add( YCPString("index"), YCPInteger((*i)->getIndex()) );
        dbList.add(ymap);
    }
    return dbList;
}

YCPValue SlapdConfigAgent::ReadDatabase( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &opt)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    std::string dbIndexStr = path->component_str(0);
    y2milestone("Component %s ", dbIndexStr.c_str());
    int dbIndex = -2;
    if ( dbIndexStr[0] == '{' )
    {
        std::string::size_type pos = dbIndexStr.find('}');
        std::istringstream indexstr(dbIndexStr.substr(1, pos-1));
        indexstr >> dbIndex;
    } else {
        y2error("Database Index expected, got: %s", dbIndexStr.c_str() );
        return YCPNull();
    }
    if ( dbIndex < -1 )
    {
        y2error("Invalid database index: %d", dbIndex );
        return YCPNull();
    }

    y2milestone("Database to read: %d", dbIndex);
    OlcDatabaseList::const_iterator i;
    for ( i = databases.begin(); i != databases.end() ; i++ )
    {
        if ( (*i)->getIndex() == dbIndex ) 
        {
            YCPMap resMap;
            if ( path->length() == 1 )
            {
                resMap.add( YCPString("suffix"), 
                            YCPString( (*i)->getStringValue("olcSuffix") ));
                resMap.add( YCPString("directory"), 
                            YCPString( (*i)->getStringValue("olcDbDirectory") ));
                resMap.add( YCPString("rootdn"), 
                            YCPString( (*i)->getStringValue("olcRootDn") ));
                return resMap;
            } else {
                std::string dbComponent = path->component_str(1);
                y2milestone("Component %s ", dbComponent.c_str());
                IndexMap idx = (*i)->getIndexes();
                IndexMap::const_iterator j = idx.begin();
                for ( ; j != idx.end(); j++ )
                {
                    YCPMap ycpIdx;
                    y2milestone("indexed Attribute: \"%s\"", j->first.c_str() );
                    std::vector<IndexType>::const_iterator k = j->second.begin();
                    for ( ; k != j->second.end(); k++ )
                    {
                        if ( *k == Eq )
                            ycpIdx.add(YCPString("eq"), YCPBoolean(true) );
                    }
                    resMap.add( YCPString(j->first), ycpIdx );
                }
                return resMap;
            }
        }
    }
    return YCPNull();
}

YCPValue SlapdConfigAgent::ReadSchema( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &opt)
{
    if ( path->length() !=1 )
    {
        y2milestone("Unsupported Path: %s", path->toString().c_str() );
        return YCPNull();
    } 
    else if ( path->component_str(0) == "attributeTypes" )
    {
        if ( schema.size() == 0 )
        {
            schema = olc.getSchemaNames();
        }
        OlcSchemaList::const_iterator i;
        YCPMap resMap;
        for (i = schema.begin(); i != schema.end(); i++ )
        {
            y2milestone("Schema: %s", (*i)->getName().c_str() );
            std::vector<LDAPAttrType> types = (*i)->getAttributeTypes();
            std::vector<LDAPAttrType>::const_iterator j;
            for ( j = types.begin(); j != types.end(); j++ )
            {
                YCPMap attrMap;

                // Handling derived AttributeTypes.
                // Attention! This code assumes that supertypes have been 
                // read prior to their subtypes
                if ( j->getSuperiorOid() != "" ){
                    y2milestone("'%s' is a subtype of '%s'",j->getName().c_str(), j->getSuperiorOid().c_str() );
                    // locate Supertype

                    YCPMap supMap = resMap->value(YCPString(j->getSuperiorOid()))->asMap();
                    attrMap.add( YCPString("equality"), supMap->value(YCPString("equality")) );
                    attrMap.add( YCPString("substring"), supMap->value(YCPString("substring")) );
                    attrMap.add( YCPString("presence"), supMap->value(YCPString("presence")) );
                } else {
                    if ( j->getEqualityOid() != "" )
                    {
                        attrMap.add( YCPString("equality"), YCPBoolean( true ) );
                    } else {
                        attrMap.add( YCPString("equality"), YCPBoolean( false ) );
                    }
                    if ( j->getSubstringOid() != "" )
                    {
                        attrMap.add( YCPString("substring"), YCPBoolean( true ) );
                    } else {
                        attrMap.add( YCPString("substring"), YCPBoolean( false ) );
                    }
                    attrMap.add( YCPString("presence"), YCPBoolean( true ) );
                }

                // FIXME: how should "approx" indexing be handled, create 
                //        whitelist based upon syntaxes?
                
                resMap.add( YCPString( j->getName() ), attrMap );
            }
        }
        return resMap;
    }
    return YCPNull();
}

YCPValue SlapdConfigAgent::ReadSchemaList( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &opt)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    if ( schema.size() == 0 )
    {
        schema = olc.getSchemaNames();
    }
    OlcSchemaList::const_iterator i;
    YCPList resultList;
    for (i = schema.begin(); i != schema.end(); i++ )
    {
        if (! (*i)->getName().empty() )
        {
            resultList.add( YCPString( (*i)->getName() ) );
        }
    }
    return resultList;
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
        if ( path->component_str(0) == "loglevel" )
        {
            y2milestone("Write loglevel");
            YCPList levels = arg->asList();
            std::list<std::string> levelList;
            for ( int i = 0; i < levels->size(); i++ )
            {
                levelList.push_back( levels->value(i)->asString()->value_cstr() );
            }
            globals->setLogLevel( levelList );
            return YCPBoolean(true);
        }
        if ( path->component_str(0) == "allow" )
        {
            y2milestone("Write allow Features");
            YCPList features = arg->asList();
            std::list<std::string> featureList;
            for ( int i = 0; i < features->size(); i++ )
            {
                featureList.push_back( features->value(i)->asString()->value_cstr() );
            }
            globals->setAllowFeatures( featureList );
            return YCPBoolean(true);
        }
        if ( path->component_str(0) == "disallow" )
        {
            y2milestone("Write disallow Features");
            YCPList features = arg->asList();
            std::list<std::string> featureList;
            for ( int i = 0; i < features->size(); i++ )
            {
                featureList.push_back( features->value(i)->asString()->value_cstr() );
            }
            globals->setDisallowFeatures( featureList );
            return YCPBoolean(true);
        }
        if ( path->component_str(0) == "tlsSettings" )
        {
            y2milestone("Write TLS Settings");
            YCPMap tlsMap = arg->asMap();
            OlcTlsSettings tls( globals->getTlsSettings() );
            YCPMapIterator i= tlsMap.begin();
            for ( ; i != tlsMap.end(); i++ )
            {
                std::string key(i.key()->asString()->value_cstr() );
                y2milestone("tlsMap Key: %s", key.c_str() );
                if ( key == "caCertDir" )
                {
                    if ( ! i.value().isNull() )
                        tls.setCaCertDir(i.value()->asString()->value_cstr() );
                } 
                else if ( key == "caCertFile" )
                {
                    if ( ! i.value().isNull() )
                        tls.setCaCertFile(i.value()->asString()->value_cstr() );
                }
                else if ( key == "certFile" )
                {
                    if ( ! i.value().isNull() )
                        tls.setCertFile(i.value()->asString()->value_cstr() );
                }
                else if ( key == "certKeyFile" )
                {
                    if ( ! i.value().isNull() )
                        tls.setCertKeyFile(i.value()->asString()->value_cstr() );
                }
                else if ( key == "crlCheck" )
                {
                }
                else if ( key == "crlFile" )
                {
                    if ( ! i.value().isNull() )
                        tls.setCrlFile (i.value()->asString()->value_cstr() );
                }
                else if ( key == "verifyClient" )
                {
                }
                else
                {
                }
            }
            globals->setTlsSettings(tls);
            return YCPBoolean(true);
        }
    }
    return YCPBoolean(false);
}

YCPBoolean SlapdConfigAgent::WriteDatabase( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &arg2)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    std::string dbIndexStr = path->component_str(0);
    YCPMap changesMap= arg->asMap();
    int dbIndex = -2;
    if ( dbIndexStr[0] == '{' )
    {
        std::string::size_type pos = dbIndexStr.find('}');
        std::istringstream indexstr(dbIndexStr.substr(1, pos-1));
        indexstr >> dbIndex;
    } else {
        y2error("Database Index expected, got: %s", dbIndexStr.c_str() );
        return YCPNull();
    }
    if ( dbIndex < -1 )
    {
        y2error("Invalid database index: %d", dbIndex );
        return YCPNull();
    }

    y2milestone("Database to write: %d", dbIndex);
    OlcDatabaseList::const_iterator i;
    for ( i = databases.begin(); i != databases.end() ; i++ )
    {
        if ( (*i)->getIndex() == dbIndex ) 
        {
            YCPValue val =  changesMap.value( YCPString("rootdn") );
            if ( val->isString() )
            {
                (*i)->setStringValue( "olcRootDn", val->asString()->value_cstr() );
            }
        }
    }
    return YCPBoolean(false);
}

YCPBoolean SlapdConfigAgent::WriteSchema( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &arg2)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());

    y2milestone("WriteSchema");
    std::string subpath = path->component_str(0);
    if ( subpath == "addFromLdif" )
    {
        std::string filename = arg->asString()->value_cstr();
        y2milestone("adding Ldif File: %s", filename.c_str());
        std::ifstream ldifFile(filename.c_str());
        LdifReader ldif(ldifFile);
        if ( ldif.readNextRecord() )
        {
            LDAPEntry entry, oldEntry;
            entry = ldif.getEntryRecord();
            schema.push_back( boost::shared_ptr<OlcSchemaConfig>(new OlcSchemaConfig(oldEntry, entry)) );
        }
        return YCPBoolean(true);
    }
    if ( subpath == "remove" )
    {
        std::string name = arg->asString()->value_cstr();
        y2milestone("remove Schema Entry: %s", name.c_str());
        OlcSchemaList::const_iterator i;
        for (i = schema.begin(); i != schema.end(); i++ )
        {
            if ( (*i)->getName() == name )
            {
                (*i)->clearChangedEntry();
            }
        }
        return YCPBoolean(true);
    }
    return YCPBoolean(false);
}

YCPString SlapdConfigAgent::ConfigToLdif() const
{
    y2milestone("ConfigToLdif");
    OlcDatabaseList::const_iterator i = databases.begin();
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

