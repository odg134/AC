#pragma once
#include <windows.h>
#include <vector>

namespace Mapper
{
    /// <summary>
    /// Walks the process list and returns the first PID whose image name matches Name
    /// (case-insensitive). Returns 0 if not found.
    /// </summary>
    DWORD FindProcess( const wchar_t* Name );

    /// <summary>
    /// Manually maps Image (a raw PE DLL image) into Process without touching the
    /// loader: copies headers and sections, fixes base relocations, resolves the IAT
    /// from our own address space (valid for same-boot system DLLs), then spins up a
    /// remote thread at AddressOfEntryPoint to call DllMain(DLL_PROCESS_ATTACH).
    /// </summary>
    bool Map( HANDLE Process, const std::vector<BYTE>& Image );
}
