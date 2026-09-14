#include <Misc/Incl.h>
#include <Core/Environment/Environment.h>
#include <Core/Environment/PG/PG.h>

namespace Environment
{
    NTSTATUS Check( )
    {
        NTSTATUS Result = STATUS_SUCCESS;

        // PG integrity...
        //
        NTSTATUS S = PG::VerifyPresence( );
        if ( !NT_SUCCESS( S ) )
        {
            LogWarn( "Environment: PG check failed: {}", S );
            if ( NT_SUCCESS( Result ) ) Result = S;
        }

        return Result;
    }
}
