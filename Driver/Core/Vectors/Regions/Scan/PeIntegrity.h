#pragma once
#include <ntddk.h>
#include <Core/Vectors/Regions/Modules/Modules.h>
#include <Core/Vectors/Regions/Scan/Walk.h>

namespace Regions::Scan
{
    /// <summary>
    /// For each loaded module's executable PE sections, checks that the PTE's
    /// NoExecute bit matches the section's declared permissions.
    /// A section marked executable whose pages have NX=1 indicates PTE manipulation.
    /// </summary>
    /// <param name="Modules"></param>
    /// <param name="Buffer"></param>
    void CheckPeIntegrity( const Modules::Snapshot& Modules, FindingBuffer& Buffer );
}
