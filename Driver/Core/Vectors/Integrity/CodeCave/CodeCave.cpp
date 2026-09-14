#include <Misc/Incl.h>
#pragma pack(push)
#include <ntimage.h>
#pragma pack(pop)
#include "CodeCave.h"

namespace Integrity::CodeCave
{
    // Locate a section by name within the already-loaded image (virtual layout).
    //
    static bool FindSection(
        PVOID Base, ULONG ImageSize,
        const char* Name,
        ULONG* OutVa, ULONG* OutVirtSize )
    {
        auto* Dos = static_cast< IMAGE_DOS_HEADER* >( Base );
        if ( Dos->e_magic != IMAGE_DOS_SIGNATURE )
            return false;

        if ( (ULONG)Dos->e_lfanew + sizeof( IMAGE_NT_HEADERS64 ) > ImageSize )
            return false;

        auto* Nt = reinterpret_cast< IMAGE_NT_HEADERS64* >(
            static_cast< UCHAR* >( Base ) + Dos->e_lfanew );
        if ( Nt->Signature != IMAGE_NT_SIGNATURE )
            return false;

        ULONG NameLen = 0;
        while ( Name[NameLen] ) ++NameLen;

        auto* Sec = reinterpret_cast< IMAGE_SECTION_HEADER* >(
            reinterpret_cast< UCHAR* >( &Nt->OptionalHeader ) +
            Nt->FileHeader.SizeOfOptionalHeader );

        for ( USHORT i = 0; i < Nt->FileHeader.NumberOfSections; ++i )
        {
            if ( RtlCompareMemory( Sec[i].Name, Name, NameLen ) == NameLen &&
                ( NameLen == 8 || Sec[i].Name[NameLen] == '\0' ) )
            {
                *OutVa       = Sec[i].VirtualAddress;
                *OutVirtSize = Sec[i].Misc.VirtualSize
                    ? Sec[i].Misc.VirtualSize
                    : Sec[i].SizeOfRawData;
                return true;
            }
        }

        return false;
    }

    // Check whether offset Rva is covered by any RUNTIME_FUNCTION entry.
    //
    static bool IsCovered(
        const IMAGE_RUNTIME_FUNCTION_ENTRY* Funcs, ULONG Count, ULONG Rva )
    {
        for ( ULONG i = 0; i < Count; ++i )
        {
            if ( Rva >= Funcs[i].BeginAddress && Rva < Funcs[i].EndAddress )
                return true;
        }
        return false;
    }

    // True if all bytes in [Ptr, Ptr+Len) are INT3 (0xCC) or zero.
    //
    static bool IsPadding( const UCHAR* Ptr, ULONG Len )
    {
        for ( ULONG i = 0; i < Len; ++i )
        {
            if ( Ptr[i] != 0x00 && Ptr[i] != 0xCC )
                return false;
        }
        return true;
    }

    static void CheckModule( const Scan::ModuleEntry& Mod, FindingList& Out )
    {
        if ( !Mod.DllBase || !Mod.SizeOfImage )
            return;

        auto* Base = static_cast< UCHAR* >( Mod.DllBase );
        const CHAR* Name = Scan::BaseName( Mod );

        ULONG TextVa = 0, TextVirtSize = 0;
        if ( !FindSection( Mod.DllBase, Mod.SizeOfImage, ".text", &TextVa, &TextVirtSize ) )
            return;

        // Locate the exception directory (.pdata) from the in-memory optional header.
        //
        auto* Dos = reinterpret_cast< IMAGE_DOS_HEADER* >( Base );
        if ( Dos->e_magic != IMAGE_DOS_SIGNATURE )
            return;

        auto* Nt = reinterpret_cast< IMAGE_NT_HEADERS64* >( Base + Dos->e_lfanew );
        auto& ExDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

        if ( !ExDir.VirtualAddress || !ExDir.Size )
            return;

        if ( ExDir.VirtualAddress + ExDir.Size > Mod.SizeOfImage )
            return;

        auto* Funcs = reinterpret_cast< IMAGE_RUNTIME_FUNCTION_ENTRY* >(
            Base + ExDir.VirtualAddress );
        ULONG FuncCount = ExDir.Size / sizeof( IMAGE_RUNTIME_FUNCTION_ENTRY );

        // Scan the in-memory .text section for runs of non-padding bytes that
        // have no corresponding RUNTIME_FUNCTION entry.
        //
        const UCHAR* Text     = Base + TextVa;
        ULONG        i        = 0;

        while ( i < TextVirtSize )
        {
            if ( !MmIsAddressValid( const_cast< UCHAR* >( Text + i ) ) )
            {
                ++i;
                continue;
            }

            // Skip over padding bytes.
            //
            if ( Text[i] == 0x00 || Text[i] == 0xCC )
            {
                ++i;
                continue;
            }

            // Non-padding byte found. Check pdata coverage.
            //
            ULONG Rva = TextVa + i;
            if ( IsCovered( Funcs, FuncCount, Rva ) )
            {
                ++i;
                continue;
            }

            // Uncovered non-padding byte — measure the run.
            //
            ULONG Start = i;
            while ( i < TextVirtSize )
            {
                UCHAR B = ( MmIsAddressValid( const_cast< UCHAR* >( Text + i ) ) ) ? Text[i] : 0xCC;
                if ( B == 0x00 || B == 0xCC )
                    break;
                if ( IsCovered( Funcs, FuncCount, TextVa + i ) )
                    break;
                ++i;
            }

            ULONG RunLen = i - Start;
            if ( RunLen >= MinSuspectRun )
            {
                Out.Add( FindingKind::CodeCave, Mod.DllBase, TextVa + Start, RunLen, Name );
                if ( Out.Count >= MaxFindings )
                    return;
            }
        }
    }

    void Scan( const Scan::ModuleList& Modules, FindingList& Out )
    {
        for ( ULONG i = 0; i < Modules.Count && Out.Count < MaxFindings; ++i )
            CheckModule( Modules.Entries[i], Out );
    }
}
