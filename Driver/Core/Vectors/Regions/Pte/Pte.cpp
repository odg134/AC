#include <Misc/Incl.h>
#pragma pack(push)
#include <ntimage.h>
#pragma pack(pop)
#include <Misc/Libraries/Zydis/Zydis.h>
#include <Core/Vectors/Regions/Pte/Pte.h>

namespace Regions::Pte
{
    static ULONG64 g_PteBase = 0;

    struct KldrEntry
    {
        LIST_ENTRY InLoadOrderLinks;
        PVOID      ExceptionTable;
        ULONG      ExceptionTableSize;
        ULONG      Pad0;
        PVOID      GpValue;
        PVOID      NonPagedDebugInfo;
        PVOID      DllBase;
        PVOID      EntryPoint;
        ULONG      SizeOfImage;
    };

    extern "C" NTKERNELAPI LIST_ENTRY PsLoadedModuleList;

    /// <summary>
    /// Scans ntoskrnl for MiGetPteAddress to extract the per-boot PTE base.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Resolve( )
    {
        // First entry of PsLoadedModuleList is always ntoskrnl.
        //
        auto* Entry = reinterpret_cast< KldrEntry* >( PsLoadedModuleList.Flink );
        if ( !Entry )
            return STATUS_NOT_FOUND;

        auto* Base = reinterpret_cast< UCHAR* >( Entry->DllBase );
        if ( !Base )
            return STATUS_NOT_FOUND;

        auto* Dos = reinterpret_cast< IMAGE_DOS_HEADER* >( Base );
        if ( Dos->e_magic != IMAGE_DOS_SIGNATURE )
            return STATUS_NOT_FOUND;

        auto* Nt = reinterpret_cast< IMAGE_NT_HEADERS* >( Base + Dos->e_lfanew );
        if ( Nt->Signature != IMAGE_NT_SIGNATURE )
            return STATUS_NOT_FOUND;

        PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION( Nt );
        ULONG64 TextStart = 0;
        ULONG64 TextEnd   = 0;

        for ( USHORT i = 0; i < Nt->FileHeader.NumberOfSections; ++i )
        {
            if ( RtlCompareMemory( Sec[i].Name, ".text", 5 ) == 5 )
            {
                TextStart = reinterpret_cast< ULONG64 >( Base ) + Sec[i].VirtualAddress;
                TextEnd   = TextStart + Sec[i].Misc.VirtualSize;
                break;
            }
        }

        if ( !TextStart )
            return STATUS_NOT_FOUND;

        ZydisDecoder Decoder;
        ZydisDecoderInit( &Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64 );

        for ( ULONG64 Va = TextStart; Va < TextEnd; )
        {
            ZydisDecodedInstruction I1;
            ZydisDecodedOperand O1[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( &Decoder, reinterpret_cast< void* >( Va ), TextEnd - Va, &I1, O1 ) ) )
            {
                Va++; continue;
            }

            // SHR RCX, 9
            if ( I1.mnemonic != ZYDIS_MNEMONIC_SHR ||
                 O1[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                 O1[0].reg.value != ZYDIS_REGISTER_RCX ||
                 O1[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                 O1[1].imm.value.u != 9 )
            {
                Va += I1.length; continue;
            }

            ULONG64 N = Va + I1.length;

            ZydisDecodedInstruction I2, I3, I4;
            ZydisDecodedOperand O2[ZYDIS_MAX_OPERAND_COUNT],
                                O3[ZYDIS_MAX_OPERAND_COUNT],
                                O4[ZYDIS_MAX_OPERAND_COUNT];

            // MOV RAX, 7FFFFFFFF8h
            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( &Decoder, reinterpret_cast< void* >( N ), TextEnd - N, &I2, O2 ) ) ||
                 I2.mnemonic != ZYDIS_MNEMONIC_MOV ||
                 O2[0].reg.value != ZYDIS_REGISTER_RAX ||
                 O2[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                 O2[1].imm.value.u != 0x7FFFFFFFF8ULL )
            {
                Va += I1.length; continue;
            }

            N += I2.length;

            // AND RCX, RAX
            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( &Decoder, reinterpret_cast< void* >( N ), TextEnd - N, &I3, O3 ) ) ||
                 I3.mnemonic != ZYDIS_MNEMONIC_AND ||
                 O3[0].reg.value != ZYDIS_REGISTER_RCX ||
                 O3[1].reg.value != ZYDIS_REGISTER_RAX )
            {
                Va += I1.length; continue;
            }

            N += I3.length;

            // MOV RAX, <PTE_BASE>
            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( &Decoder, reinterpret_cast< void* >( N ), TextEnd - N, &I4, O4 ) ) ||
                 I4.mnemonic != ZYDIS_MNEMONIC_MOV ||
                 O4[0].reg.value != ZYDIS_REGISTER_RAX ||
                 O4[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE )
            {
                Va += I1.length; continue;
            }

            g_PteBase = O4[1].imm.value.u;
            LogTrace( "Regions: PTE base = {}", reinterpret_cast< void* >( g_PteBase ) );
            return STATUS_SUCCESS;
        }

        return STATUS_NOT_FOUND;
    }

    static ULONG64 PteAddressOf( ULONG64 Va )
    {
        return ( ( Va >> 9 ) & 0x7FFFFFFFF8ULL ) + g_PteBase;
    }

    /// <summary>
    /// Returns the virtual address of the PTE for Va.
    /// </summary>
    HardwarePte* GetPte( PVOID Va )
    {
        return reinterpret_cast< HardwarePte* >( PteAddressOf( reinterpret_cast< ULONG64 >( Va ) ) );
    }

    /// <summary>
    /// Returns the virtual address of the PDE for Va.
    /// </summary>
    HardwarePte* GetPde( PVOID Va )
    {
        return reinterpret_cast< HardwarePte* >( PteAddressOf( PteAddressOf( reinterpret_cast< ULONG64 >( Va ) ) ) );
    }

    /// <summary>
    /// Returns the virtual address of the PDPTE for Va.
    /// </summary>
    HardwarePte* GetPdpte( PVOID Va )
    {
        return reinterpret_cast< HardwarePte* >(
            PteAddressOf( PteAddressOf( PteAddressOf( reinterpret_cast< ULONG64 >( Va ) ) ) ) );
    }

    /// <summary>
    /// Returns the virtual address of the PML4E for Va.
    /// </summary>
    HardwarePte* GetPml4e( PVOID Va )
    {
        return reinterpret_cast< HardwarePte* >(
            PteAddressOf( PteAddressOf( PteAddressOf( PteAddressOf( reinterpret_cast< ULONG64 >( Va ) ) ) ) ) );
    }

    bool IsExecutable( const HardwarePte& Pte )
    {
        return Pte.Present && !Pte.NoExecute;
    }

    bool IsRwx( const HardwarePte& Pte )
    {
        return Pte.Present && Pte.Writable && !Pte.NoExecute;
    }
}
