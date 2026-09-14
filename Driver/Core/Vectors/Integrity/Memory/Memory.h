#pragma once
#include <ntddk.h>
#include <Core/Vectors/Integrity/Integrity.h>
#include <Core/Vectors/Integrity/Scan/Scan.h>

namespace Integrity::Memory
{
    void Scan( const Scan::ModuleList& Modules, FindingList& Out );
}
