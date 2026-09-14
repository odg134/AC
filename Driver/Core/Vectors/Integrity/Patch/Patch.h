#pragma once
#include <ntddk.h>
#include <Core/Vectors/Integrity/Integrity.h>
#include <Core/Vectors/Integrity/Scan/Scan.h>

namespace Integrity::Patch
{
    // Maximum on-disk image size we're willing to read for comparison.
    // Drivers larger than this are skipped to bound pool usage.
    //
    static constexpr ULONG MaxImageBytes = 4 * 1024 * 1024;

    void Scan( const Scan::ModuleList& Modules, FindingList& Out );
}
