#ifndef BACK_CONFIG_TEST_H
#define BACK_CONFIG_TEST_H
#include <LDAPConnection.h>
#include <LDAPResult.h>
#include <string>
#include <iostream>
#include <sstream>
#include <map>
#include <vector>
#include <LDAPEntry.h>

class OlcConfigEntry
{
    public:
        static OlcConfigEntry* createFromLdapEntry( const LDAPEntry& le);
        static bool isDatabaseEntry( const LDAPEntry& le);
        static bool isScheamEntry( const LDAPEntry& le);
        static bool isOverlayEntry( const LDAPEntry& le);
        static bool isGlobalEntry( const LDAPEntry& le);

        inline OlcConfigEntry() : m_dbEntry(), m_dbEntryChanged() {}
        inline OlcConfigEntry(const LDAPEntry& le) : m_dbEntry(le), m_dbEntryChanged(le) {}
        inline std::string getDn() { 
            return m_dbEntry.getDN();
        }
        LDAPModList entryDifftoMod();
        
        StringList getStringValues(const std::string &type) const;
        void setStringValues(const std::string &type, const StringList &values);

        // shortcuts for single-valued Attributes
        std::string getStringValue(const std::string &type) const;
        void setStringValue(const std::string &type, const std::string &value);

        void setIndex( int index );
        void getEntryDn();

        virtual std::map<std::string, std::list<std::string> > toMap() const;
        virtual std::string toLdif() const;

    protected:
        virtual void updateEntryDn();

        int entryIndex;
        LDAPEntry m_dbEntry;
        LDAPEntry m_dbEntryChanged;
};

class OlcDatabase : public OlcConfigEntry
{
    public :
        static OlcDatabase* createFromLdapEntry( const LDAPEntry& le );
        
        OlcDatabase( const LDAPEntry &le );
        OlcDatabase( const std::string& type );
        static bool isBdbDatabase( const LDAPEntry& le );
        
        void setSuffix( const std::string &suffix);
        void setRootDn( const std::string &rootdn);
        void setRootPw( const std::string &rootpw);

        virtual std::map<std::string, std::list<std::string> > toMap() const;
    
    protected:
        virtual void updateEntryDn();
        std::string m_type;

};

class OlcBdbDatabase : public  OlcDatabase 
{
    public:
        OlcBdbDatabase();
        OlcBdbDatabase( const LDAPEntry& le );
        virtual std::map<std::string, std::list<std::string> > toMap() const;
        void setDirectory( const std::string &dir);
        
        enum IndexType {
            Default,
            Present,
            Eq,
            Approx,
            Sub,
            SpecialSubInitial,
            SpecialSubAny,
            SpecialSubFinal,
            SpecialNoLang,
            SpecialNoSubTypes,
        };

        typedef std::map<std::string, std::vector<OlcBdbDatabase::IndexType> > IndexMap;
        IndexMap getIndexes();
};

class OlcTlsSettings;

class OlcGlobalConfig : public OlcConfigEntry 
{
    public:
        OlcGlobalConfig();
        inline OlcGlobalConfig( const LDAPEntry &le) : OlcConfigEntry(le) {}
        int getLogLevel() const;
        const std::vector<std::string> getLogLevelString() const;
        void setLogLevel(int level);
        void setLogLevel(std::string level);
        void addLogLevel(std::string level);
        OlcTlsSettings getTlsSettings() const;
        virtual std::map<std::string, std::list<std::string> > toMap() const;
};

class OlcSchemaConfig : public OlcConfigEntry
{
    public:
        OlcSchemaConfig();
};

class OlcConfig {
    public:
        OlcConfig(LDAPConnection *lc=0 );
        OlcGlobalConfig getGlobals();
        void setGlobals( OlcGlobalConfig &olcg);
        OlcBdbDatabase getDatabase(std::string &basedn);
    private:
        LDAPConnection *m_lc;
};

class OlcTlsSettings {
    public :
        OlcTlsSettings( const OlcGlobalConfig &le );
        int getCrlCheck() const;
        void setCrlCheck();
        int getVerifyClient() const;
        void setVerifyClient();
        const std::string& getCaCertDir() const;
        const std::string& getCaCertFile() const;

    private:
        int m_crlCheck;
        int m_verifyCient;
        std::string m_caCertDir;
        std::string m_caCertFile;
};

#endif /* BACK_CONFIG_TEST_H */
