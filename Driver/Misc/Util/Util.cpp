#include <Misc/Incl.h>
#include <Core/Mem/Mem.h>
#include "Util.h"

extern "C" NTSTATUS ZwQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength );

namespace Util
{

    struct ModuleEntry
    {
        HANDLE Section;
        PVOID  MappedBase;
        PVOID  ImageBase;
        ULONG  ImageSize;
        ULONG  Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR  FullPathName[256];
    };

    struct ModuleList
    {
        ULONG       Count;
        ModuleEntry Modules[1];
    };

    static constexpr ULONG SystemModuleInformation = 11;

    static bool MatchName( const UCHAR* Path, const char* Name )
    {
        ULONG NLen = 0;
        while ( Name[NLen] ) ++NLen;

        ULONG PLen = 0;
        while ( Path[PLen] ) ++PLen;

        if ( NLen > PLen )
            return false;

        const UCHAR* Suffix = Path + PLen - NLen;

        for ( ULONG i = 0; i < NLen; ++i )
        {
            UCHAR A = Suffix[i];
            UCHAR B = ( UCHAR )Name[i];
            if ( A >= 'A' && A <= 'Z' ) A += 32;
            if ( B >= 'A' && B <= 'Z' ) B += 32;
            if ( A != B ) return false;
        }

        return true;
    }

    /// <summary>
    /// Queries the loaded module list for a driver by file name (e.g. "ntfs.sys").
    /// Case-insensitive suffix match on the full path.
    /// </summary>
    /// <param name="Name"></param>
    /// <param name="Out"></param>
    /// <returns></returns>
    bool QueryDriver( const char* Name, DriverInfo* Out )
    {
        ULONG Needed = 0;
        ZwQuerySystemInformation( SystemModuleInformation, nullptr, 0, &Needed );
        if ( Needed == 0 )
            return false;

        Needed += 1024;
        auto* Buf = ( ModuleList* )Mem::Alloc( Needed );
        if ( !Buf )
            return false;

        NTSTATUS Status = ZwQuerySystemInformation( SystemModuleInformation, Buf, Needed, nullptr );
        if ( !NT_SUCCESS( Status ) )
        {
            Mem::Free( Buf );
            return false;
        }

        bool Found = false;
        for ( ULONG i = 0; i < Buf->Count; ++i )
        {
            if ( !MatchName( Buf->Modules[i].FullPathName, Name ) )
                continue;

            if ( Out )
            {
                Out->Base = Buf->Modules[i].ImageBase;
                Out->Size = Buf->Modules[i].ImageSize;
            }

            Found = true;
            break;
        }

        Mem::Free( Buf );
        return Found;
    }

    /// <summary>
    /// Returns the loaded base address of a driver by file name, or nullptr if not found.
    /// </summary>
    /// <param name="Name"></param>
    /// <returns></returns>
    PVOID DriverBase( const char* Name )
    {
        DriverInfo Info{};
        return QueryDriver( Name, &Info ) ? Info.Base : nullptr;
    }

    /// <summary>
    /// Returns the image size of a driver by file name, or 0 if not found.
    /// </summary>
    /// <param name="Name"></param>
    /// <returns></returns>
    ULONG DriverSize( const char* Name )
    {
        DriverInfo Info{};
        return QueryDriver( Name, &Info ) ? Info.Size : 0;
    }

} // namespace Util
