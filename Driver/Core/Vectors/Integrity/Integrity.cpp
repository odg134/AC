#include <Misc/Incl.h>
#include <Core/Mem/Mem.h>
#include "Integrity.h"
#include "Scan/Scan.h"
#include "Patch/Patch.h"
#include "CodeCave/CodeCave.h"
#include "Memory/Memory.h"

namespace Integrity
{
    NTSTATUS Scan( FindingList* Out )
    {
        auto* Modules = Mem::New< Scan::ModuleList >();
        if ( !Modules )
            return STATUS_INSUFFICIENT_RESOURCES;

        NTSTATUS Status = Scan::Enumerate( Modules );
        if ( !NT_SUCCESS( Status ) )
        {
            Mem::Delete( Modules );
            LogWarn( "Integrity: module enumeration failed ({})", Status );
            return Status;
        }

        Log( "Integrity: scanning {} loaded modules", Modules->Count );

        Patch::Scan( *Modules, *Out );
        Log( "Integrity: patch scan complete ({} findings)", Out->Count );

        CodeCave::Scan( *Modules, *Out );
        Log( "Integrity: code cave scan complete ({} findings)", Out->Count );

        Memory::Scan( *Modules, *Out );
        Log( "Integrity: memory scan complete ({} findings)", Out->Count );

        Mem::Delete( Modules );
        return STATUS_SUCCESS;
    }
}
