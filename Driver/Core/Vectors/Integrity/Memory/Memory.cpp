#include <Misc/Incl.h>
#include "Memory.h"

extern "C" NTSTATUS ZwQueryVirtualMemory(
    HANDLE                       ProcessHandle,
    PVOID                        BaseAddress,
    ULONG                        MemoryInformationClass,
    PVOID                        MemoryInformation,
    SIZE_T                       MemoryInformationLength,
    PSIZE_T                      ReturnLength );

namespace Integrity::Memory
{
    // Protection flags for executable pages.
    //
    static constexpr ULONG ExecMask  = PAGE_EXECUTE | PAGE_EXECUTE_READ
                                     | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    static constexpr ULONG WriteMask = PAGE_READWRITE | PAGE_WRITECOPY
                                     | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

    static constexpr ULONG MemTypeCommit  = 0x1000;
    static constexpr ULONG MemTypePrivate = 0x20000;
    static constexpr ULONG MemTypeImage   = 0x1000000;

    // MemoryBasicInformation class.
    //
    static constexpr ULONG MemoryBasicInformation = 0;

    struct BasicInfo
    {
        PVOID  BaseAddress;
        PVOID  AllocationBase;
        ULONG  AllocationProtect;
        SIZE_T RegionSize;
        ULONG  State;
        ULONG  Protect;
        ULONG  Type;
    };

    // True when the address [Base, Base+Size) falls within a known loaded module.
    //
    static bool InModuleRange(
        PVOID Base, const Scan::ModuleList& Modules )
    {
        auto Addr = reinterpret_cast< ULONG_PTR >( Base );
        for ( ULONG i = 0; i < Modules.Count; ++i )
        {
            auto MBase = reinterpret_cast< ULONG_PTR >( Modules.Entries[i].DllBase );
            if ( Addr >= MBase && Addr < MBase + Modules.Entries[i].SizeOfImage )
                return true;
        }
        return false;
    }

    void Scan( const Scan::ModuleList& Modules, FindingList& Out )
    {
        // Determine the scan start address from the lowest loaded module base,
        // then walk forward through kernel VA.
        //
        ULONG_PTR ScanStart = 0xFFFF800000000000ULL;
        for ( ULONG i = 0; i < Modules.Count; ++i )
        {
            auto Addr = reinterpret_cast< ULONG_PTR >( Modules.Entries[i].DllBase );
            if ( Addr && Addr < ScanStart )
                ScanStart = Addr;
        }

        PVOID Addr = reinterpret_cast< PVOID >( ScanStart );
        const ULONG MaxIterations = 1500;

        for ( ULONG Iter = 0; Iter < MaxIterations && Out.Count < MaxFindings; ++Iter )
        {
            BasicInfo Mbi{};
            SIZE_T    RetLen = 0;

            NTSTATUS St = ZwQueryVirtualMemory(
                ZwCurrentProcess(), Addr, MemoryBasicInformation,
                &Mbi, sizeof( Mbi ), &RetLen );

            if ( !NT_SUCCESS( St ) || !Mbi.RegionSize )
            {
                // Advance by 64KB and keep scanning.
                //
                Addr = reinterpret_cast< PVOID >(
                    reinterpret_cast< ULONG_PTR >( Addr ) + 0x10000 );
                continue;
            }

            if ( Mbi.State != MEM_COMMIT )
            {
                Addr = reinterpret_cast< PVOID >(
                    reinterpret_cast< ULONG_PTR >( Mbi.BaseAddress ) + Mbi.RegionSize );
                continue;
            }

            ULONG Prot = Mbi.Protect & 0xFF;  // strip guard/no-cache modifiers

            bool IsExec  = ( Prot & ExecMask  ) != 0;
            bool IsWrite = ( Prot & WriteMask ) != 0;

            if ( IsExec )
            {
                bool InModule = InModuleRange( Mbi.AllocationBase, Modules );

                // MEM_PRIVATE executable region not inside any loaded module.
                //
                if ( Mbi.Type == MEM_PRIVATE && !InModule )
                {
                    Out.Add( FindingKind::Unbacked,
                        nullptr,
                        static_cast< ULONG >(
                            reinterpret_cast< ULONG_PTR >( Mbi.BaseAddress ) ),
                        static_cast< ULONG >( Mbi.RegionSize ),
                        nullptr );
                }

                // Any RWX region, even within an image, is suspicious.
                //
                if ( IsWrite && IsExec )
                {
                    // Find the module name if the region falls in a loaded image.
                    //
                    const CHAR* ModName = nullptr;
                    PVOID       ModBase = nullptr;
                    for ( ULONG i = 0; i < Modules.Count; ++i )
                    {
                        auto MBase = reinterpret_cast< ULONG_PTR >(
                            Modules.Entries[i].DllBase );
                        auto MEnd  = MBase + Modules.Entries[i].SizeOfImage;
                        auto RBase = reinterpret_cast< ULONG_PTR >( Mbi.BaseAddress );

                        if ( RBase >= MBase && RBase < MEnd )
                        {
                            ModName = Scan::BaseName( Modules.Entries[i] );
                            ModBase = Modules.Entries[i].DllBase;
                            break;
                        }
                    }

                    ULONG Offset = ModBase
                        ? static_cast< ULONG >(
                            reinterpret_cast< ULONG_PTR >( Mbi.BaseAddress ) -
                            reinterpret_cast< ULONG_PTR >( ModBase ) )
                        : static_cast< ULONG >(
                            reinterpret_cast< ULONG_PTR >( Mbi.BaseAddress ) );

                    Out.Add( FindingKind::Rwx,
                        ModBase,
                        Offset,
                        static_cast< ULONG >( Mbi.RegionSize ),
                        ModName );
                }
            }

            Addr = reinterpret_cast< PVOID >(
                reinterpret_cast< ULONG_PTR >( Mbi.BaseAddress ) + Mbi.RegionSize );
        }
    }
}
