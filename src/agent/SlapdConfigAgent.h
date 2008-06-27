/* SlapdConfigAgent.h
 *
 * Authors: Ralf Haferkamp <rhafer@suse.de>
 *
 * $Id$
 */

#ifndef _SlapdConfigAgent_h
#define _SlapdConfigAgent_h

#include <Y2.h>
#include <scr/SCRAgent.h>
#include <boost/shared_ptr.hpp>
#include "backConfigTest.h"
/**
 * @short An interface class between YaST2 and Ldap Agent
 */
class SlapdConfigAgent : public SCRAgent {
    public :
        SlapdConfigAgent();
        virtual ~SlapdConfigAgent();
        virtual YCPValue Read( const YCPPath &path,
                               const YCPValue &arg = YCPNull(),
                               const YCPValue &opt = YCPNull());

        virtual YCPBoolean Write( const YCPPath &path,
                                const YCPValue &arg,
                                const YCPValue &arg2 = YCPNull());

        virtual YCPValue Execute( const YCPPath &path,
                                  const YCPValue &arg = YCPNull(),
                                  const YCPValue &arg2 = YCPNull());

        virtual YCPList Dir( const YCPPath &path);

        virtual YCPValue otherCommand( const YCPTerm& term);

    protected:
        YCPValue ReadGlobal( const YCPPath &path,
                             const YCPValue &arg = YCPNull(),
                             const YCPValue &opt = YCPNull());

        YCPValue ReadDatabases( const YCPPath &path,
                             const YCPValue &arg = YCPNull(),
                             const YCPValue &opt = YCPNull());
        YCPBoolean WriteGlobal( const YCPPath &path,
                             const YCPValue &arg = YCPNull(),
                             const YCPValue &opt = YCPNull());
        YCPString ConfigToLdif() const;

    private:
        OlcConfig olc;
        std::list<boost::shared_ptr<OlcDatabase> > databases;
        boost::shared_ptr<OlcGlobalConfig> globals;
        boost::shared_ptr<OlcSchemaConfig> schemaBase;
};

#endif /* _SlapdConfigAgent_h */

