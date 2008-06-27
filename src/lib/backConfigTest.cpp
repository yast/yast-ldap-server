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

inline void splitIndexString( const std::string &indexString, std::string &attr, std::string &indexes )
{
    std::string::size_type pos = indexString.find_first_of(" \t");
    attr = indexString.substr(0, pos);
    std::cout << "AttributeType: <" << attr << ">" << std::endl;
    if ( pos != std::string::npos ) {
        pos = indexString.find_first_not_of(" \t", pos);
        if ( pos != std::string::npos ) {
            indexes = indexString.substr( pos, std::string::npos );
        }
    }
}

inline std::vector<IndexType> indexString2Type( const std::string &indexes )
{
    std::string::size_type pos, oldpos = 0;
    std::vector<IndexType> idx;
    do {
        pos = indexes.find( ',', oldpos );
        std::string index = indexes.substr( oldpos, 
                    (pos == std::string::npos ? std::string::npos : pos - oldpos) );
        std::cout << "Index: <" << index << ">" << std::endl;
        oldpos = indexes.find_first_not_of( ", ", pos );
        if ( index == "pres" ) {
            idx.push_back(Present);
        } else if (index == "eq" ) {
            idx.push_back(Eq);
        } else if (index == "approx" ) {
            idx.push_back(Approx);
        } else if (index == "sub" ) {
            idx.push_back(Sub);
        } else if (index == "subinital" ) {
            idx.push_back(SpecialSubInitial);
        } else if (index == "subany" ) {
            idx.push_back(SpecialSubAny);
        } else if (index == "subfinal" ) {
            idx.push_back(SpecialSubFinal);
        } else if (index == "nolang" ) {
            idx.push_back(SpecialNoLang);
        } else if (index == "nosubtypes" ) {
            idx.push_back(SpecialNoSubTypes);
        }
    } while (pos != std::string::npos);
    return idx;
}

IndexMap OlcBdbDatabase::getDatabaseIndexes() const
{
    const LDAPAttributeList *al = m_dbEntryChanged.getAttributes();
    const LDAPAttribute *attr = al->getAttributeByName("olcdbindex");
    IndexMap res;
    if (! attr ) {
        return res;
    };

    StringList sl = attr->getValues();
    StringList::const_iterator i;
    for (i = sl.begin(); i != sl.end(); i++ ) {
        std::string attrType;
        std::string indexes;
        splitIndexString(*i, attrType, indexes );
        std::cout << "Indexes: <" << indexes << ">" << std::endl;
        std::vector<IndexType> idx = indexString2Type(indexes);
        res.insert(make_pair(attrType, idx));
    }
    return res;
}

std::vector<IndexType> OlcBdbDatabase::getDatabaseIndex( const std::string &type ) const
{
    const LDAPAttributeList *al = m_dbEntryChanged.getAttributes();
    const LDAPAttribute *attr = al->getAttributeByName("olcdbindex");
    std::vector<IndexType> res;
    if (! attr ) {
        return res;
    };

    StringList sl = attr->getValues();
    StringList::const_iterator i;
    for (i = sl.begin(); i != sl.end(); i++ ) {
        std::string attrType;
        std::string indexes;
        splitIndexString(*i, attrType, indexes );
        if ( attrType == type )
        {
            res = indexString2Type(indexes);
            break;
        }
    }
    return res;
}

void OlcBdbDatabase::addIndex(const std::string& attr, const std::vector<IndexType>& idx)
{
    std::string indexString = attr;
    std::vector<IndexType>::const_iterator i;
    bool first = true;
    for ( i = idx.begin(); i != idx.end(); i++ )
    {
        if (! first)
        {
            indexString += ",";
        } else {
            indexString += " ";
            first = false;
        }
        if ( *i == Present ) {
            indexString += "pres";
        }
        else if ( *i == Eq )
        {
            indexString += "eq";
        }
        else if ( *i == Sub )
        {
            indexString += "sub";
        }
    }
    std::cout << "indexString: '" << indexString << "'" << std::endl;
    this->addStringValue( "olcDbIndex", indexString );
}

void OlcBdbDatabase::deleteIndex(const std::string& type)
{
    const LDAPAttribute *attr = m_dbEntryChanged.getAttributes()->getAttributeByName("olcdbindex");
    if (! attr ) {
        return;
    };
    
    StringList sl = attr->getValues();
    StringList newValues;
    StringList::const_iterator i;
    for (i = sl.begin(); i != sl.end(); i++ ) {
        std::string attrType;
        std::string indexes;
        splitIndexString(*i, attrType, indexes );
        if ( attrType != type )
        {
            newValues.add(*i);
        }
    }
    this->setStringValues("olcdbindex", newValues );
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

OlcGlobalConfig::OlcGlobalConfig( const LDAPEntry &le) : OlcConfigEntry(le)
{
    std::cout << "OlcGlobalConfig::OlcGlobalConfig( const LDAPEntry &le) : OlcConfigEntry(le)" << std::endl;

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
            std::cerr << "IntegerValue " << *i << std::endl;
        }
        else
        {
            std::cerr << "StringValue " << *i << std::endl;
            lvls.push_back(*i);
        }
    }
    return lvls;
}

//int OlcGlobalConfig::getIdleTimeout() 
//{
//
//}

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

const std::vector<std::string> OlcGlobalConfig::getAllowFeatures() const
{
    StringList values = this->getStringValues("olcAllows");
    StringList::const_iterator i;
    std::vector<std::string> allow;
    for ( i = values.begin(); i != values.end(); i++ )
    {
        allow.push_back(*i);
    }
    return allow;
}

void OlcGlobalConfig::setAllowFeatures(const std::list<std::string> &allow )
{
    const LDAPAttribute *sattr = m_dbEntryChanged.getAttributeByName("olcAllows");
    LDAPAttribute attr( "olcAllows" );
    if ( sattr ) {
        attr = *sattr;
    }
    StringList values;
    std::list<std::string>::const_iterator i = allow.begin();
    for(; i != allow.end(); i++ )
    {
        values.add(*i);
    }
    attr.setValues(values);
    m_dbEntryChanged.replaceAttribute(attr);
}

const std::vector<std::string> OlcGlobalConfig::getDisallowFeatures() const
{
    StringList values = this->getStringValues("olcDisallows");
    StringList::const_iterator i;
    std::vector<std::string> allow;
    for ( i = values.begin(); i != values.end(); i++ )
    {
        allow.push_back(*i);
    }
    return allow;
}

void OlcGlobalConfig::setDisallowFeatures(const std::list<std::string> &disallow )
{
    const LDAPAttribute *sattr = m_dbEntryChanged.getAttributeByName("olcDisallows");
    LDAPAttribute attr( "olcDisallows" );
    if ( sattr ) {
        attr = *sattr;
    }
    StringList values;
    std::list<std::string>::const_iterator i = disallow.begin();
    for(; i != disallow.end(); i++ )
    {
        values.add(*i);
    }
    attr.setValues(values);
    m_dbEntryChanged.replaceAttribute(attr);
}


OlcSchemaConfig::OlcSchemaConfig() : OlcConfigEntry()
{
    m_dbEntryChanged.setDN("cn=schema,cn=config");
    m_dbEntryChanged.addAttribute(LDAPAttribute("objectclass", "olcSchemaConfig"));
    m_dbEntryChanged.addAttribute(LDAPAttribute("cn", "schema"));
}

OlcSchemaConfig::OlcSchemaConfig(const LDAPEntry &e) : OlcConfigEntry(e)
{
    std::cout << "OlcSchemaConfig::OlcSchemaConfig(const LDAPEntry &e) : OlcConfigEntry(e)" << std::endl;
    std::string name(this->getStringValue("cn"));
    if ( name[0] == '{' )
    {
        std::string::size_type pos = name.find('}');
        std::istringstream indexstr(name.substr(1, pos-1));
        indexstr >> entryIndex;
        m_name = name.substr( pos+1, std::string::npos );
    } else {
        m_name = name;
        entryIndex = 0;
    }
}
OlcSchemaConfig::OlcSchemaConfig(const LDAPEntry &e1, const LDAPEntry &e2) : OlcConfigEntry(e1, e2)
{
    std::cout << "OlcSchemaConfig::OlcSchemaConfig(const LDAPEntry &e) : OlcConfigEntry(e)" << std::endl;
    std::string name(this->getStringValue("cn"));
    if ( name[0] == '{' )
    {
        std::string::size_type pos = name.find('}');
        std::istringstream indexstr(name.substr(1, pos-1));
        indexstr >> entryIndex;
        m_name = name.substr( pos+1, std::string::npos );
    } else {
        m_name = name;
        entryIndex = 0;
    }
}

void OlcSchemaConfig::clearChangedEntry()
{
    OlcConfigEntry::clearChangedEntry();
    m_name = "";
}

const std::string& OlcSchemaConfig::getName() const
{
    return m_name;
}

const std::vector<LDAPAttrType> OlcSchemaConfig::getAttributeTypes() const
{
    std::vector<LDAPAttrType> res;
    StringList types = this->getStringValues("olcAttributeTypes");
    StringList::const_iterator j;
    for ( j = types.begin(); j != types.end(); j++ )
    {
        LDAPAttrType currentAttr;
        if ( (*j)[0] == '{' )
        {
            std::string::size_type pos = j->find('}');
            currentAttr = LDAPAttrType( j->substr( pos+1, std::string::npos ) );
        } else {
            currentAttr = LDAPAttrType( *j );
        }
        res.push_back(currentAttr);
    }
    return res;
}

OlcTlsSettings OlcGlobalConfig::getTlsSettings() const 
{
    std::cout << "OlcTlsSettings OlcGlobalConfig::getTlsSettings() const " << std::endl;
    return OlcTlsSettings( *this );
}

void OlcGlobalConfig::setTlsSettings( const OlcTlsSettings& tls )
{
    tls.applySettings( *this );
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
        return new OlcSchemaConfig(e);
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

int OlcConfigEntry::getEntryIndex() const
{
    return this->entryIndex;
}

void OlcConfigEntry::updateEntryDn()
{
}

void OlcConfigEntry::clearChangedEntry()
{
        m_dbEntryChanged = LDAPEntry();     
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

void OlcConfigEntry::addStringValue(const std::string &type, const std::string &value)
{
    const LDAPAttribute *attr =  m_dbEntryChanged.getAttributeByName(type);
    if ( attr ) {
        LDAPAttribute newAttr(*attr);
        newAttr.addValue(value);
        m_dbEntryChanged.replaceAttribute(newAttr);
    } else {
        LDAPAttribute newAttr(type, value);
        m_dbEntryChanged.addAttribute(newAttr);
    }
}

std::string OlcConfigEntry::toLdif() const
{
    std::ostringstream ldifStream;
    LdifWriter ldif(ldifStream);
    ldif.writeRecord( m_dbEntryChanged );
    return ldifStream.str();
}

bool OlcConfigEntry::isNewEntry() const
{
    return ( this->getDn().empty() );
}
bool OlcConfigEntry::isDeletedEntry() const
{
    return ( (!this->getDn().empty()) && this->getUpdatedDn().empty() );
}

LDAPModList OlcConfigEntry::entryDifftoMod() const {
    LDAPAttributeList::const_iterator i = m_dbEntry.getAttributes()->begin();
    LDAPModList modifications;
    std::cout << "Old Entry DN: " << m_dbEntry.getDN() << std::endl;
    std::cout << "New Entry DN: " << m_dbEntryChanged.getDN() << std::endl;
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
                if ( (addValues.size() > 0) && ( (int)delValues.size() == i->getNumValues()) ) {
                    std::cout << "All Values deleted, this is a replace" << std::endl;
                    modifications.addModification(
                            LDAPModification( LDAPAttribute(i->getName(), addValues), 
                                    LDAPModification::OP_REPLACE) 
                            );
                    replace = true;
                } else {
                    modifications.addModification(
                            LDAPModification( LDAPAttribute(i->getName(), delValues ), 
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
    i = m_dbEntryChanged.getAttributes()->begin();
    for(; i != m_dbEntryChanged.getAttributes()->end(); i++ )
    {
        std::cout << i->getName() << std::endl;
        const LDAPAttribute *old =  m_dbEntry.getAttributeByName(i->getName());
        if (! old ) {
            std::cout << "Attribute added: " << i->getName() << std::endl;
            if (! i->getValues().empty() )
            {
                modifications.addModification(
                        LDAPModification( LDAPAttribute(i->getName(), i->getValues()), 
                                    LDAPModification::OP_ADD) 
                        );
            }
        }
    }
    return modifications;
}

OlcConfig::OlcConfig(LDAPConnection *lc) : m_lc(lc)
{
    
}

boost::shared_ptr<OlcGlobalConfig> OlcConfig::getGlobals()
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
        boost::shared_ptr<OlcGlobalConfig> gc( new OlcGlobalConfig(*dbEntry) );
        return gc;
    }
    boost::shared_ptr<OlcGlobalConfig> gc( new OlcGlobalConfig() );
    return gc;
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

void OlcConfig::updateEntry( const OlcConfigEntry &oce )
{
    try {
        if ( oce.isNewEntry () ) 
        {
            m_lc->add(&oce.getChangedEntry());
        } else if (oce.isDeletedEntry() ) {
            m_lc->del(oce.getDn());
        } else {
            LDAPModList ml = oce.entryDifftoMod();
            if ( ! ml.empty() ) {
                m_lc->modify( oce.getDn(), &ml );
            } else {
                std::cout << oce.getDn() << ": no changes" << std::endl;
            }
        }
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

OlcSchemaList OlcConfig::getSchemaNames()
{
    OlcSchemaList res;
    try {
        StringList attrs;
        LDAPSearchResults *sr = m_lc->search( "cn=schema,cn=config", 
                LDAPConnection::SEARCH_SUB, "objectclass=olcSchemaConfig" );
        LDAPEntry *entry;
        while ( entry = sr->getNext() )
        {
            std::cout << "Got Schema Entry: " << entry->getDN() << std::endl;
            boost::shared_ptr<OlcSchemaConfig> olce(new OlcSchemaConfig(*entry));
            res.push_back(olce);
        }
    } catch (LDAPException e ) {
        std::cout << e << std::endl;
        throw;
    }
    return res;
}

OlcTlsSettings::OlcTlsSettings( const OlcGlobalConfig &ogc )
    : m_crlCheck(0), m_verifyCient(0)
{
    std::cout << "OlcTlsSettings::OlcTlsSettings( const OlcGlobalConfig &ogc )" << std::endl;
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
    m_certFile = ogc.getStringValue("olcTlsCertificateFile");
    m_certKeyFile = ogc.getStringValue("olcTlsCertificateKeyFile");
    m_crlFile = ogc.getStringValue("olcTlsCrlFile");
}

void OlcTlsSettings::applySettings( OlcGlobalConfig &ogc ) const
{
    std::cout << "OlcTlsSettings::applySettings( OlcGlobalConfig &ogc )" << std::endl;
    ogc.setStringValue("olcTlsCaCertificatePath", m_caCertDir);
    ogc.setStringValue("olcTlsCaCertificateFile", m_caCertFile);
    ogc.setStringValue("olcTlsCertificateFile", m_certFile);
    ogc.setStringValue("olcTlsCertificateKeyFile", m_certKeyFile);
    ogc.setStringValue("olcTlsCrlFile", m_crlFile);
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

const std::string& OlcTlsSettings::getCertFile() const 
{
    return m_certFile;
}
const std::string& OlcTlsSettings::getCertKeyFile() const 
{
    return m_certKeyFile;
}
const std::string& OlcTlsSettings::getCrlFile() const 
{
    return m_crlFile;
}

void OlcTlsSettings::setCaCertDir(const std::string& dir)
{
    m_caCertDir = dir;
}

void OlcTlsSettings::setCaCertFile(const std::string& file)
{
    m_caCertFile = file;
}

void OlcTlsSettings::setCertFile(const std::string& file)
{
    m_certFile = file;
}

void OlcTlsSettings::setCertKeyFile(const std::string& file)
{
    m_certKeyFile = file;
}

void OlcTlsSettings::setCrlFile(const std::string& file)
{
    m_crlFile = file;
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
        OlcBdbDatabase::IndexMap idx = db.getDatabaseIndexes();
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
