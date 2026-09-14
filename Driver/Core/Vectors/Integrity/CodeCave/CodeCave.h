#pragma once
#include <ntddk.h>
#include <Core/Vectors/Integrity/Integrity.h>
#include <Core/Vectors/Integrity/Scan/Scan.h>

namespace Integrity::CodeCave
{
    // Minimum run of non-padding executable bytes that must lack RUNTIME_FUNCTION
    // coverage before we flag it as a code cave.
    //
    static constexpr ULONG MinSuspectRun = 64;

    void Scan( const Scan::ModuleList& Modules, FindingList& Out );
}
