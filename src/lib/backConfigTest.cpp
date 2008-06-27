#include <LDAPConnection.h>
#include <LDAPResult.h>
#include <string>
#include <iostream>
#include <sstream>
#include <map>
#include <vector>
#include <LDAPEntry.h>
#include <LdifWriter.h>
#include "backConfigTest.h"

static bool nocase_compare( char c1, char c2){
    return toupper(c1) == toupper(c2);
}

static bool strCaseIgnoreEquals(const std::string &s1, const std::string &s2)
{
    if(s1.size() == s2.size()){
        if(equal(s1.begin(), s1.end(), s2.begin(),
                nocase_compare)){
            return true;
        }
    }
    return false;
}

OlcDatabase::OlcDatabase( const LDAPEntry& le=LDAPEntry()) : OlcConfigEntry(le)
{
    std::string type(this->getStringValue("olcdatabase"));
    if ( type[0] == '{' )
    {
        std::string::size_type pos = type.find('}');
        std::istringstream indexstr(type.substr(1, pos-1));
        indexstr >> entryIndex;
        m_type = type.substr( pos+1, std::string::npos );
    } else {
        m_type = type;
        entryIndex = 0;
    }
}

OlcDatabase::OlcDatabase( const std::string& type ) : m_type(type) 
{
    std::ostringstream dnstr;
    dnstr << "olcDatabase=" << m_type << ",cn=config";
    m_dbEntryChanged.setDN(dnstr.str());
    m_dbEntryChanged.addAttribute(LDAPAttribute("objectclass", "olcDatabaseConfig"));
    m_dbEntryChanged.addAttribute(LDAPAttribute("olcDatabase", m_type));
}

void OlcDatabase::updateEntryDn()
{
    std::cerr << "updateEntryDN()" << std::endl;
    std::ostringstream dn, name;
    name << "{" << entryIndex << "}" << m_type;
    dn << "olcDatabase=" << name.str() << ",cn=config" ;
    m_dbEntryChanged.setDN(dn.str());
    m_dbEntryChanged.replaceAttribute(LDAPAttribute("olcDatabase", name.str()));
}

OlcBdbDatabase::OlcBdbDatabase() : OlcDatabase("bdb") 
{ 
    m_dbEntryChanged.addAttribute(LDAPAttribute("objectclass", "olcBdbConfig"));
}

OlcBdbDatabase::OlcBdbDatabase( const LDAPEntry& le) : OlcDatabase(le) { }

OlcBdbDatabase::IndexMap OlcBdbDatabase::getIndexes()
{
    const LDAPAttributeList *al = m_dbEntry.getAttributes();
    const LDAPAttribute *attr = al->getAttributeByName("olcdbindex");
    OlcBdbDatabase::IndexMap res;
    StringList sl = attr->getValues();
    StringList::const_iterator i;
    for (i = sl.begin(); i != sl.end(); i++ ) {
        std::cout << "Index Value: " << *i << std::endl;
        std::string::size_type pos = i->find_first_of(" \t");
        std::string attrType = i->substr(0, pos);
        std::cout << "AttributeType: <" << attrType << ">" << std::endl;
        std::string indexes;
        if ( pos != std::string::npos ) {
            pos = i->find_first_not_of(" \t", pos);
            if ( pos != std::string::npos ) {
                indexes = i->substr( pos, std::string::npos );
                std::cout << "Indexes: <" << indexes << ">" << std::endl;
                std::string::size_type oldpos = 0;
                std::vector<OlcBdbDatabase::IndexType> idx;
                do {
                    pos = indexes.find( ',', oldpos );
                    std::string index = indexes.substr( oldpos, 
                                (pos == std::string::npos ? std::string::npos : pos - oldpos) );
                    std::cout << "Index: <" << index << ">" << std::endl;
                    oldpos = indexes.find_first_not_of( ", ", pos );
                    if ( index == "pres" ) {
                        idx.push_back(OlcBdbDatabase::Present);
                    } else if (index == "eq" ) {
                        idx.push_back(OlcBdbDatabase::Eq);
                    } else if (index == "approx" ) {
                        idx.push_back(OlcBdbDatabase::Approx);
                    } else if (index == "sub" ) {
                        idx.push_back(OlcBdbDatabase::Sub);
                    } else if (index == "subinital" ) {
                        idx.push_back(OlcBdbDatabase::SpecialSubInitial);
                    } else if (index == "subany" ) {
                        idx.push_back(OlcBdbDatabase::SpecialSubAny);
                    } else if (index == "subfinal" ) {
                        idx.push_back(OlcBdbDatabase::SpecialSubFinal);
                    } else if (index == "nolang" ) {
                        idx.push_back(OlcBdbDatabase::SpecialNoLang);
                    } else if (index == "nosubtypes" ) {
                        idx.push_back(OlcBdbDatabase::SpecialNoSubTypes);
                    }
                } while (pos != std::string::npos);
                res.insert(make_pair(attrType, idx));
            }
        }
    }
    return res;
}

void OlcBdbDatabase::setDirectory( const std::string &dir )
{   
    this->setStringValue("olcDbDirectory", dir);
}

OlcGlobalConfig::OlcGlobalConfig() : OlcConfigEntry()
{
    m_dbEntryChanged.setDN("cn=config");
    m_dbEntryChanged.addAttribute(LDAPAttribute("objectclass", "olcGlobal"));
    m_dbEntryChanged.addAttribute(LDAPAttribute("cn", "config"));
}

int OlcGlobalConfig::getLogLevel() const 
{
    const LDAPAttribute *attr = m_dbEntryChanged.getAttributeByName("olcloglevel");
    if (attr) {
        StringList sl = attr->getValues();
        StringList::const_iterator i;
        for (i = sl.begin(); i != sl.end(); i++ ) {
            std::cout << "loglevel: " << *i << std::endl;
        }
    } else {
        return 0;
    }
}

const std::vector<std::string> OlcGlobalConfig::getLogLevelString() const
{
    StringList lvalues = this->getStringValues("olcLogLevel");
    StringList::const_iterator i;
    std::vector<std::string> lvls;
    for ( i = lvalues.begin(); i != lvalues.end(); i++ )
    {
        std::istringstream iss(*i);
        int intlogValue;
        if ( iss >> intlogValue ) {
            std::cerr << "IntegerValue" << *i << std::endl;
        }
        else
        {
            std::cerr << "StringValue" << *i << std::endl;
            lvls.push_back(*i);
        }
    }
    return lvls;
}

//int OlcGlobalConfig::getIdleTimeout() 
//{
//
//}

void OlcGlobalConfig::setLogLevel(int level) {
    const LDAPAttribute *sattr = m_dbEntryChanged.getAttributeByName("olcloglevel");
    LDAPAttribute attr;
    if ( sattr ) {
        attr = *sattr;
    }
    std::ostringstream o;
    StringList values;
    o << level;
    values.add(o.str());
    attr.setValues(values);
    m_dbEntryChanged.replaceAttribute(attr);
}

void OlcGlobalConfig::setLogLevel(const std::list<std::string> &level) {
    const LDAPAttribute *sattr = m_dbEntryChanged.getAttributeByName("olcloglevel");
    LDAPAttribute attr( "olcloglevel" );
    if ( sattr ) {
        attr = *sattr;
    }
    StringList values;
    std::list<std::string>::const_iterator i = level.begin();
    for(; i != level.end(); i++ )
    {
        values.add(*i);
    }
    attr.setValues(values);
    m_dbEntryChanged.replaceAttribute(attr);
}

void OlcGlobalConfig::addLogLevel(std::string level) {
    const LDAPAttribute *sattr = m_dbEntryChanged.getAttributeByName("olcloglevel");
    LDAPAttribute attr;
    if ( sattr ) {
        attr = *sattr;
    }
    attr.addValue(level);
    m_dbEntryChanged.replaceAttribute(attr);
}

OlcSchemaConfig::OlcSchemaConfig() : OlcConfigEntry()
{
    m_dbEntryChanged.setDN("cn=schema,cn=config");
    m_dbEntryChanged.addAttribute(LDAPAttribute("objectclass", "olcSchemaConfig"));
    m_dbEntryChanged.addAttribute(LDAPAttribute("cn", "schema"));
}

OlcTlsSettings OlcGlobalConfig::getTlsSettings() const {
    return OlcTlsSettings( m_dbEntryChanged );
}

std::map<std::string, std::list<std::string> > OlcGlobalConfig::toMap() const
{
    std::map<std::string, std::list<std::string> > resMap;
    const LDAPAttribute *at = m_dbEntryChanged.getAttributeByName("olcsuffix");
    if ( at ) 
    {
        StringList values = at->getValues();
        StringList::const_iterator j;
        std::list<std::string> valList;
        for ( j = values.begin(); j != values.end(); j++ )
        {
            valList.push_back(*j);
        }
        resMap.insert(std::make_pair("suffix", valList));
    }
    at = m_dbEntryChanged.getAttributeByName("olcDatabase");
    if ( at ) 
    {
        StringList values = at->getValues();
        StringList::const_iterator j;
        std::list<std::string> valList;
        for ( j = values.begin(); j != values.end(); j++ )
        {
            valList.push_back(*j);
        }
        resMap.insert(std::make_pair("type", valList));
    }
    return resMap;
}

bool OlcConfigEntry::isDatabaseEntry ( const LDAPEntry& e )
{
    StringList oc = e.getAttributeByName("objectclass")->getValues();
    for( StringList::const_iterator i = oc.begin(); i != oc.end(); i++ )
    {
        if ( strCaseIgnoreEquals(*i, "olcDatabaseConfig" ) )
        {
            return true;
        }
    }
    return false;
}

bool OlcConfigEntry::isGlobalEntry ( const LDAPEntry& e )
{
    StringList oc = e.getAttributeByName("objectclass")->getValues();
    for( StringList::const_iterator i = oc.begin(); i != oc.end(); i++ )
    {
        if ( strCaseIgnoreEquals(*i, "olcGlobal" ) )
        {
            return true;
        }
    }
    return false;
}

bool OlcConfigEntry::isOverlayEntry ( const LDAPEntry& e )
{
    StringList oc = e.getAttributeByName("objectclass")->getValues();
    for( StringList::const_iterator i = oc.begin(); i != oc.end(); i++ )
    {
        if ( strCaseIgnoreEquals(*i, "olcOverlayConfig" ) )
        {
            return true;
        }
    }
    return false;
}

bool OlcConfigEntry::isScheamEntry ( const LDAPEntry& e )
{
    StringList oc = e.getAttributeByName("objectclass")->getValues();
    for( StringList::const_iterator i = oc.begin(); i != oc.end(); i++ )
    {
        if ( strCaseIgnoreEquals(*i, "olcSchemaConfig" ) )
        {
            return true;
        }
    }
    return false;
}

OlcConfigEntry* OlcConfigEntry::createFromLdapEntry( const LDAPEntry& e )
{
    if ( OlcConfigEntry::isGlobalEntry(e) )
    {
        std::cerr << "creating OlcGlobalConfig" << std::endl;
        return new OlcGlobalConfig(e);
    }
    else if ( OlcConfigEntry::isScheamEntry(e) )
    {
        std::cerr << "creating OlcSchemaConfig" << std::endl;
        return new OlcConfigEntry(e);
    }
    else if ( OlcConfigEntry::isDatabaseEntry(e) )
    {
        std::cerr << "creating OlcDatabase" << std::endl;
        return OlcDatabase::createFromLdapEntry(e);
    }
    else if ( OlcConfigEntry::isOverlayEntry(e) )
    {
        std::cerr << "creating OlcOverlay" << std::endl;
        return new OlcConfigEntry(e);
    }
    else
    {
        std::cerr << "unknown Config Object" << std::endl;
        return 0;
    }
}

std::map<std::string, std::list<std::string> > OlcConfigEntry::toMap() const
{
    std::map<std::string, std::list<std::string> > resMap;
//    std::string value = this->getStringValue("olcConcurrency");
//    resMap.insert( std::make_pair( "concurrency", value ) );
//
//    value = this->getStringValue("olcThreads");
//    resMap.insert( std::make_pair("threads", value ) );

    return resMap;
}

void OlcConfigEntry::setIndex( int index )
{
    this->entryIndex = index;
    this->updateEntryDn();
}

int OlcConfigEntry::getIndex() const
{
    return this->entryIndex;
}

void OlcConfigEntry::updateEntryDn()
{
}

std::map<std::string, std::list<std::string> > OlcDatabase::toMap() const
{
    std::map<std::string, std::list<std::string> > resMap;
    const LDAPAttribute *at = m_dbEntryChanged.getAttributeByName("olcsuffix");
    if ( at ) 
    {
        StringList values = at->getValues();
        StringList::const_iterator j;
        std::list<std::string> valList;
        for ( j = values.begin(); j != values.end(); j++ )
        {
            valList.push_back(*j);
        }
        resMap.insert(std::make_pair("suffix", valList));
    }
    at = m_dbEntryChanged.getAttributeByName("olcDatabase");
    if ( at ) 
    {
        StringList values = at->getValues();
        StringList::const_iterator j;
        std::list<std::string> valList;
        for ( j = values.begin(); j != values.end(); j++ )
        {
            valList.push_back(*j);
        }
        resMap.insert(std::make_pair("type", valList));
    }
    return resMap;
}

void OlcDatabase::setSuffix( const std::string &suffix)
{
    this->setStringValue("olcSuffix", suffix); 
}

void OlcDatabase::setRootDn( const std::string &rootdn)
{
    this->setStringValue("olcRootDN", rootdn); 
}

void OlcDatabase::setRootPw( const std::string &rootpw)
{
    this->setStringValue("olcRootPW", rootpw); 
}

const std::string OlcDatabase::getSuffix() const
{
    return this->getStringValue("olcSuffix");
}

const std::string OlcDatabase::getType() const
{
    return this->m_type;
}

std::map<std::string, std::list<std::string> > OlcBdbDatabase::toMap() const
{
    std::map<std::string, std::list<std::string> > resMap = 
            OlcDatabase::toMap();

    const LDAPAttribute *at = m_dbEntryChanged.getAttributeByName("olcDbNoSync");
    if ( at )
    {
        StringList values = at->getValues();
        StringList::const_iterator j;
        std::list<std::string> valList;
        for ( j = values.begin(); j != values.end(); j++ )
        {
            valList.push_back(*j);
        }
        resMap.insert(std::make_pair("nosync", valList));
    }
    return resMap;
}

bool OlcDatabase::isBdbDatabase( const LDAPEntry& e )
{
    StringList oc = e.getAttributeByName("objectclass")->getValues();
    for( StringList::const_iterator i = oc.begin(); i != oc.end(); i++ )
    {
        if ( strCaseIgnoreEquals(*i, "olcBdbConfig" ) )
        {
            return true;
        }
    }
    return false;
}

OlcDatabase* OlcDatabase::createFromLdapEntry( const LDAPEntry& e)
{
    if ( OlcDatabase::isBdbDatabase( e ) )
    {
        std::cerr << "creating OlcBbdDatabase()" << std::endl;
        return new OlcBdbDatabase(e);
    }
    else
    {
        std::cerr << "creating OlcDatabase()" << std::endl;
        return new OlcDatabase(e);
    }
}

StringList OlcConfigEntry::getStringValues(const std::string &type) const
{
    const LDAPAttribute *attr = m_dbEntryChanged.getAttributeByName(type);
    if ( attr ) {
        return attr->getValues();
    } else {
        return StringList();
    }
}

std::string OlcConfigEntry::getStringValue(const std::string &type) const
{
    StringList sl = this->getStringValues(type);
    if ( sl.size() == 1 ) {
        return *(sl.begin());
    } else {
        return "";
    }
}

void OlcConfigEntry::setStringValues(const std::string &type, const StringList &values)
{
    LDAPAttribute attr(type, values);
    m_dbEntryChanged.replaceAttribute(attr);
}

void OlcConfigEntry::setStringValue(const std::string &type, const std::string &value)
{
    LDAPAttribute attr(type, value);
    m_dbEntryChanged.replaceAttribute(attr);
}

std::string OlcConfigEntry::toLdif() const
{
    std::ostringstream ldifStream;
    LdifWriter ldif(ldifStream);
    ldif.writeRecord( m_dbEntryChanged );
    return ldifStream.str();
}

LDAPModList OlcConfigEntry::entryDifftoMod() {
    LDAPAttributeList::const_iterator i = m_dbEntry.getAttributes()->begin();
    LDAPModList modifications;
    for(; i != m_dbEntry.getAttributes()->end(); i++ )
    {
        std::cout << i->getName() << std::endl;
        const LDAPAttribute *changedAttr =  m_dbEntryChanged.getAttributeByName(i->getName());
        if ( changedAttr ) {
            StringList::const_iterator j = i->getValues().begin();
            StringList delValues, addValues;
            for(; j != i->getValues().end(); j++ )
            {
                bool deleted = true;
                StringList::const_iterator k = changedAttr->getValues().begin();
                for( ; k != changedAttr->getValues().end(); k++ ) {
                    if ( *k == *j ) {
                        deleted = false;
                        break;
                    }
                }
                if ( deleted ) 
                {
                    delValues.add(*j);
                    std::cout << "Value deleted: " << *j << std::endl;
                }
            }
            j = changedAttr->getValues().begin();
            for(; j != changedAttr->getValues().end(); j++ )
            {
                bool added = true;
                StringList::const_iterator k = i->getValues().begin();
                for( ; k != i->getValues().end(); k++ ) {
                    if ( *k == *j ) {
                        std::cout << "Value unchanged: " << *k << std::endl;
                        added = false;
                        break;
                    }
                }
                if ( added ) 
                {
                    addValues.add(*j);
                    std::cout << "Value added: " << *j << std::endl;
                }
            }
            bool replace = false;
            if ( delValues.size() > 0 ) {
                if ( (int) delValues.size() == i->getNumValues() ) {
                    std::cout << "All Values deleted, this is a replace" << std::endl;
                    modifications.addModification(
                            LDAPModification( LDAPAttribute(i->getName(), addValues), 
                                    LDAPModification::OP_REPLACE) 
                            );
                    replace = true;
                } else {
                    modifications.addModification(
                            LDAPModification( LDAPAttribute(i->getName(), delValues), 
                                    LDAPModification::OP_DELETE) 
                            );
                }
            }
            if (addValues.size() > 0 && !replace ) {
                modifications.addModification(
                        LDAPModification( LDAPAttribute(i->getName(), addValues), 
                                LDAPModification::OP_ADD) 
                        );
            }
        } else {
            std::cout << "removed Attribute: " << i->getName() << std::endl;
            modifications.addModification(
                    LDAPModification( LDAPAttribute(i->getName()), 
                            LDAPModification::OP_DELETE)
                    );
        }
    }
    return modifications;
}

OlcConfig::OlcConfig(LDAPConnection *lc) : m_lc(lc)
{
    
}

OlcGlobalConfig OlcConfig::getGlobals()
{
    LDAPSearchResults *sr;
    LDAPEntry *dbEntry;
    try {
        sr = m_lc->search( "cn=config", LDAPConnection::SEARCH_BASE);
        dbEntry = sr->getNext();
    } catch (LDAPException e) {
        std::cout << e << std::endl;
        throw;
    }
    if ( dbEntry ) {
        std::cout << "Got GlobalConfig: " << dbEntry->getDN() << std::endl;
        OlcGlobalConfig gc(*dbEntry);
        return gc;
    }
    return OlcGlobalConfig();
}

void OlcConfig::setGlobals( OlcGlobalConfig &olcg)
{
    try {
        LDAPModList ml = olcg.entryDifftoMod();
        m_lc->modify( olcg.getDn(), &ml );
    } catch (LDAPException e) {
        std::cout << e << std::endl;
        throw;
    }
}

OlcDatabaseList OlcConfig::getDatabases()
{
    OlcDatabaseList res;
    try {
        LDAPSearchResults *sr = m_lc->search( "cn=config", 
                LDAPConnection::SEARCH_ONE, "objectclass=olcDatabaseConfig" );
        LDAPEntry *dbEntry;
        while ( dbEntry = sr->getNext() )
        {
            std::cout << "Got Database Entry: " << dbEntry->getDN() << std::endl;
            boost::shared_ptr<OlcDatabase> olce(OlcDatabase::createFromLdapEntry(*dbEntry));
            res.push_back(olce);
        }
    } catch (LDAPException e ) {
        std::cout << e << std::endl;
        throw;
    }
    return res;
}

OlcTlsSettings::OlcTlsSettings( const OlcGlobalConfig &ogc )
{
    std::string value = ogc.getStringValue("olcTLSCRLCheck");
    if ( value == "none" )
    {
        m_crlCheck = 0;
    }
    else if ( value == "peer" )
    {
        m_crlCheck = 1;
    }
    else if ( value == "all" )
    {
        m_crlCheck = 2;
    }
    value = ogc.getStringValue("olcTLSVerifyClient");
    if ( value == "never" )
    {
        m_verifyCient = 0;
    }
    else if ( value == "allow" )
    {
        m_verifyCient = 1;
    }
    else if ( value == "try" )
    {
        m_verifyCient = 2;
    }
    else if ( value == "demand" )
    {
        m_verifyCient = 3;
    }

    m_caCertDir = ogc.getStringValue("olcTlsCaCertificatePath");
    m_caCertFile = ogc.getStringValue("olcTlsCaCertificateFile");
}

int OlcTlsSettings::getCrlCheck() const
{
    return m_crlCheck;
}

void OlcTlsSettings::setCrlCheck()
{
}

int OlcTlsSettings::getVerifyClient() const
{
    return m_verifyCient;
}

void setVerifyClient()
{
}

const std::string& OlcTlsSettings::getCaCertDir() const
{
    return m_caCertDir;
}

const std::string& OlcTlsSettings::getCaCertFile() const 
{
    return m_caCertFile;
}

/*
int main(char** argv, int argc)
{
    LDAPConnection lc("localhost");
    LDAPSearchResults *sr;
    LDAPEntry *dbEntry;
    try {
        lc.bind("cn=config","secret");
        sr = lc.search( "olcdatabase={1}bdb,cn=config", lc.SEARCH_BASE);
        dbEntry = sr->getNext();
    } catch (LDAPException e) {
        std::cout << e << std::endl;
        exit(-1);
    }
    if ( dbEntry ) {
        std::cout << "Got DBEntry: " << dbEntry->getDN() << std::endl;
        OlcBdbDatabase db(*dbEntry);
        OlcBdbDatabase::IndexMap idx = db.getIndexes();
        OlcBdbDatabase::IndexMap::const_iterator i = idx.find("cn");

        std::cout << "Idx: " << i->second[0] << " " << OlcBdbDatabase::Eq << std::endl;
    }
    try {
        // read globalConfig
        sr = lc.search( "cn=config", lc.SEARCH_BASE);
        dbEntry = sr->getNext();
    } catch (LDAPException e) {
        std::cout << e << std::endl;
        exit(-1);
    }
    if ( dbEntry ) {
        std::cout << "Got GlobalConfig: " << dbEntry->getDN() << std::endl;
        OlcGlobalConfig gc(*dbEntry);
//        gc.getLogLevel();
//        gc.setLogLevel("stats stats2");
        std::cout << "Config file: " << gc.getStringValue("olcConfigFile")  << std::endl;
        std::cout << "args file: " << gc.getStringValue("olcArgsFile")  << std::endl;
        gc.setStringValue("olcArgsFile", "/tmp/slapd.args" );
        try {
            LDAPModList ml = gc.entryDifftoMod();
            lc.modify( dbEntry->getDN(), &ml );
        } catch (LDAPException e) {
            std::cout << e << std::endl;
            exit(-1);
        }
    } else {
        std::cout << "no Entry" << std::endl;
    }



}
*/
