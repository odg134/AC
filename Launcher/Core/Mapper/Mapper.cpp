#include <Misc/Incl.h>
#include "Mapper.h"

namespace Mapper
{
    DWORD FindProcess( const wchar_t* Name )
    {
        HANDLE Snap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
        if ( Snap == INVALID_HANDLE_VALUE )
            return 0;

        PROCESSENTRY32W Entry{};
        Entry.dwSize = sizeof( Entry );

        DWORD Pid = 0;

        if ( Process32FirstW( Snap, &Entry ) )
        {
            do
            {
                if ( _wcsicmp( Entry.szExeFile, Name ) == 0 )
                {
                    Pid = Entry.th32ProcessID;
                    break;
                }
            }
            while ( Process32NextW( Snap, &Entry ) );
        }

        CloseHandle( Snap );
        return Pid;
    }

    /// <summary>
    /// Applies base relocations to the local copy of the mapped image.
    /// Delta is (actual_base - preferred_base). Only DIR64 entries are patched (x64).
    /// </summary>
    static bool Relocate( BYTE* Base, ULONG_PTR Delta, const IMAGE_NT_HEADERS64* Nt )
    {
        if ( !Delta )
            return true;

        const auto& Dir = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
        if ( !Dir.VirtualAddress || !Dir.Size )
            return true;

        auto* Blk = reinterpret_cast< IMAGE_BASE_RELOCATION* >( Base + Dir.VirtualAddress );

        while ( Blk->VirtualAddress && Blk->SizeOfBlock >= sizeof( IMAGE_BASE_RELOCATION ) )
        {
            DWORD  Count   = ( Blk->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( USHORT );
            auto*  Entries = reinterpret_cast< USHORT* >( Blk + 1 );

            for ( DWORD I = 0; I < Count; ++I )
            {
                if ( (Entries[I] >> 12) != IMAGE_REL_BASED_DIR64 )
                    continue;

                auto* Ptr = reinterpret_cast< ULONG_PTR* >(
                    Base + Blk->VirtualAddress + (Entries[I] & 0xFFF) );
                *Ptr += Delta;
            }

            Blk = reinterpret_cast< IMAGE_BASE_RELOCATION* >(
                reinterpret_cast< BYTE* >( Blk ) + Blk->SizeOfBlock );
        }

        return true;
    }

    /// <summary>
    /// Resolves the IAT of the local image copy using GetProcAddress.
    /// System DLLs (ntdll, kernel32, etc.) are at identical VAs in every process
    /// on the same boot, so the resolved addresses are valid in the target too.
    /// </summary>
    static bool ResolveImports( BYTE* Base, const IMAGE_NT_HEADERS64* Nt )
    {
        const auto& Dir = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
        if ( !Dir.VirtualAddress )
            return true;

        auto* Desc = reinterpret_cast< IMAGE_IMPORT_DESCRIPTOR* >( Base + Dir.VirtualAddress );

        for ( ; Desc->Name; ++Desc )
        {
            const char* DllName = reinterpret_cast< const char* >( Base + Desc->Name );
            HMODULE     Mod     = LoadLibraryA( DllName );
            if ( !Mod )
                return false;

            auto* Orig = reinterpret_cast< IMAGE_THUNK_DATA* >( Base + Desc->OriginalFirstThunk );
            auto* Iat  = reinterpret_cast< IMAGE_THUNK_DATA* >( Base + Desc->FirstThunk        );

            for ( ; Orig->u1.AddressOfData; ++Orig, ++Iat )
            {
                FARPROC Fn;

                if ( IMAGE_SNAP_BY_ORDINAL( Orig->u1.Ordinal ) )
                {
                    Fn = GetProcAddress( Mod, MAKEINTRESOURCEA( IMAGE_ORDINAL( Orig->u1.Ordinal ) ) );
                }
                else
                {
                    auto* ByName = reinterpret_cast< IMAGE_IMPORT_BY_NAME* >( Base + Orig->u1.AddressOfData );
                    Fn = GetProcAddress( Mod, ByName->Name );
                }

                if ( !Fn )
                    return false;

                Iat->u1.Function = reinterpret_cast< ULONG_PTR >( Fn );
            }
        }

        return true;
    }

    bool Map( HANDLE Process, const std::vector<BYTE>& Image )
    {
        if ( Image.size( ) < sizeof( IMAGE_DOS_HEADER ) )
            return false;

        auto* Dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( Image.data( ) );
        if ( Dos->e_magic != IMAGE_DOS_SIGNATURE )
            return false;

        auto* Nt = reinterpret_cast< const IMAGE_NT_HEADERS64* >( Image.data( ) + Dos->e_lfanew );
        if ( Nt->Signature != IMAGE_NT_SIGNATURE )
            return false;

        DWORD ImageSize = Nt->OptionalHeader.SizeOfImage;

        // Build a flat virtual layout in a local scratch buffer
        //
        std::vector<BYTE> Local( ImageSize, 0 );

        memcpy( Local.data( ), Image.data( ), Nt->OptionalHeader.SizeOfHeaders );

        auto* NtLocal = reinterpret_cast< IMAGE_NT_HEADERS64* >( Local.data( ) + Dos->e_lfanew );
        auto* Sec     = IMAGE_FIRST_SECTION( NtLocal );

        for ( WORD I = 0; I < NtLocal->FileHeader.NumberOfSections; ++I )
        {
            if ( !Sec[I].SizeOfRawData )
                continue;
            memcpy( Local.data( ) + Sec[I].VirtualAddress,
                    Image.data( ) + Sec[I].PointerToRawData,
                    Sec[I].SizeOfRawData );
        }

        // Try the preferred image base, fall back to anywhere
        //
        LPVOID Remote = VirtualAllocEx( Process,
            reinterpret_cast< LPVOID >( NtLocal->OptionalHeader.ImageBase ),
            ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );

        if ( !Remote )
        {
            Remote = VirtualAllocEx( Process, nullptr,
                ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );
        }

        if ( !Remote )
            return false;

        ULONG_PTR Delta = reinterpret_cast< ULONG_PTR >( Remote )
                        - NtLocal->OptionalHeader.ImageBase;

        if ( !Relocate( Local.data( ), Delta, NtLocal ) ||
             !ResolveImports( Local.data( ), NtLocal ) )
        {
            VirtualFreeEx( Process, Remote, 0, MEM_RELEASE );
            return false;
        }

        if ( !WriteProcessMemory( Process, Remote, Local.data( ), Local.size( ), nullptr ) )
        {
            VirtualFreeEx( Process, Remote, 0, MEM_RELEASE );
            return false;
        }

        // Remote thread entry = RemoteBase + AddressOfEntryPoint
        // Passes RemoteBase as lpParameter so DllMain receives hinstDLL correctly
        //
        ULONG_PTR Entry = reinterpret_cast< ULONG_PTR >( Remote )
                        + NtLocal->OptionalHeader.AddressOfEntryPoint;

        HANDLE Thread = CreateRemoteThread( Process, nullptr, 0,
            reinterpret_cast< LPTHREAD_START_ROUTINE >( Entry ),
            Remote, 0, nullptr );

        if ( !Thread )
        {
            VirtualFreeEx( Process, Remote, 0, MEM_RELEASE );
            return false;
        }

        WaitForSingleObject( Thread, 5000 );
        CloseHandle( Thread );

        return true;
    }
}
