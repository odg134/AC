#include <Misc/Incl.h>
#pragma pack(push)
#include <ntimage.h>
#pragma pack(pop)
#include <Misc/Util/Util.h>
#include <Misc/Libraries/Zydis/Zydis.h>
#include "Offsets.h"

namespace Offsets
{

    static UINT64 GetRoutine( const wchar_t* Name )
    {
        UNICODE_STRING Str;
        RtlInitUnicodeString( &Str, Name );
        return ( UINT64 )MmGetSystemRoutineAddress( &Str );
    }

    static bool FindTextSection( PVOID Base, UINT64* OutStart, UINT64* OutSize )
    {
        auto* Dos = (PIMAGE_DOS_HEADER)Base;
        if ( Dos->e_magic != IMAGE_DOS_SIGNATURE )
            return false;

        auto* Nt = (PIMAGE_NT_HEADERS)( (PUCHAR)Base + Dos->e_lfanew );
        if ( Nt->Signature != IMAGE_NT_SIGNATURE )
            return false;

        PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION( Nt );
        for ( USHORT i = 0; i < Nt->FileHeader.NumberOfSections; ++i )
        {
            if ( RtlCompareMemory( Sec[i].Name, ".text", 5 ) == 5 )
            {
                *OutStart = ( UINT64 )Base + Sec[i].VirtualAddress;
                *OutSize = Sec[i].Misc.VirtualSize;
                return true;
            }
        }

        return false;
    }

    static UINT64 ResolveMemOp( ZydisDecodedInstruction* Instr, ZydisDecodedOperand* Op, UINT64 Va )
    {
        UINT64 Abs = 0;
        ZydisCalcAbsoluteAddress( Instr, Op, Va, &Abs );
        return Abs;
    }

    static bool VerifyKiFilterFiberContextProlog(
        UINT64 FuncStart, UINT64 Va, UINT64 TextEnd,
        ZydisDecoder* Decoder, UINT64 AddrKeKeepData )
    {
        UINT64 Limit = Va + 60;
        if ( Limit > TextEnd ) Limit = TextEnd;

        bool FoundLea = false;

        while ( Va < Limit )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Va, Limit - Va, &Instr, Ops ) ) )
                break;

            if ( !FoundLea &&
                Instr.mnemonic == ZYDIS_MNEMONIC_LEA &&
                Ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                Ops[0].reg.value == ZYDIS_REGISTER_RCX &&
                Ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                Ops[1].mem.base == ZYDIS_REGISTER_RIP )
            {
                if ( ResolveMemOp( &Instr, &Ops[1], Va ) == FuncStart )
                    FoundLea = true;
            }
            else if ( FoundLea &&
                Instr.mnemonic == ZYDIS_MNEMONIC_CALL &&
                Ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                Ops[0].mem.base == ZYDIS_REGISTER_RIP )
            {
                if ( *( UINT64* )ResolveMemOp( &Instr, &Ops[0], Va ) == AddrKeKeepData )
                    return true;
            }

            Va += Instr.length;
        }

        return false;
    }

    // Find KiFilterFiberContext via its KdDisableDebugger/KeKeepData prologue...
    //
    static NTSTATUS ResolveKiFilterFiberContext( ZydisDecoder* Decoder, UINT64 TextStart, UINT64 TextEnd )
    {
        UINT64 AddrKdDisableDebugger = GetRoutine( L"KdDisableDebugger" );
        UINT64 AddrKeKeepData = GetRoutine( L"KeKeepData" );

        if ( !AddrKdDisableDebugger || !AddrKeKeepData )
        {
            LogError( "Offsets: KdDisableDebugger or KeKeepData not found" );
            return STATUS_NOT_FOUND;
        }

        for ( UINT64 Va = TextStart; Va < TextEnd; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Va, TextEnd - Va, &Instr, Ops ) ) )
            {
                Va++; continue;
            }

            if ( Instr.mnemonic == ZYDIS_MNEMONIC_CALL &&
                Ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                Ops[0].mem.base == ZYDIS_REGISTER_RIP )
            {
                UINT64 IatSlot = ResolveMemOp( &Instr, &Ops[0], Va );
                if ( *( UINT64* )IatSlot == AddrKdDisableDebugger )
                {
                    if ( VerifyKiFilterFiberContextProlog( Va, Va + Instr.length, TextEnd, Decoder, AddrKeKeepData ) )
                    {
                        KiFilterFiberContext = Va;
                        Log( "Offsets: KiFilterFiberContext -> {}", Va );
                        return STATUS_SUCCESS;
                    }
                }
            }

            Va += Instr.length;
        }

        LogError( "Offsets: KiFilterFiberContext not found" );
        return STATUS_NOT_FOUND;
    }

    // Extract MaxDataSize, CallbackHealthFlag, PsIntegrityCheckEnabled from the
    // first three CMP [RIP+x], 0 instructions inside KiFilterFiberContext...
    //
    static NTSTATUS ExtractGlobalsFromKiFilterFiberContext( ZydisDecoder* Decoder )
    {
        UINT64 End = KiFilterFiberContext + 0x500;
        int Count = 0;

        for ( UINT64 Va = KiFilterFiberContext; Va < End; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Va, End - Va, &Instr, Ops ) ) )
            {
                Va++; continue;
            }

            if ( Instr.mnemonic == ZYDIS_MNEMONIC_CMP &&
                Ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                Ops[0].mem.base == ZYDIS_REGISTER_RIP &&
                Ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                Ops[1].imm.value.s == 0 )
            {
                UINT64 Target = ResolveMemOp( &Instr, &Ops[0], Va );

                switch ( Count++ )
                {
                case 0:
                    MaxDataSize = ( UINT64* )Target;
                    Log( "Offsets: MaxDataSize -> {}", Target );
                    break;
                case 1:
                    CallbackHealthFlag = ( UINT32* )Target;
                    Log( "Offsets: CallbackHealthFlag -> {}", Target );
                    break;
                case 2:
                    PsIntegrityCheckEnabled = ( UINT32* )Target;
                    Log( "Offsets: PsIntegrityCheckEnabled -> {}", Target );
                    break;
                }

                if ( Count == 3 )
                    break;
            }

            Va += Instr.length;
        }

        if ( Count < 3 )
        {
            LogError( "Offsets: only {} of 3 globals found in KiFilterFiberContext", Count );
            return STATUS_NOT_FOUND;
        }

        return STATUS_SUCCESS;
    }

    static void CrossCheckMaxDataSize( ZydisDecoder* Decoder, UINT64 TextStart, UINT64 TextEnd )
    {
        ZydisDecodedInstruction Prev{};

        for ( UINT64 Va = TextStart; Va < TextEnd; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Va, TextEnd - Va, &Instr, Ops ) ) )
            {
                Va++; continue;
            }

            if ( Prev.mnemonic == ZYDIS_MNEMONIC_JS &&
                Instr.mnemonic == ZYDIS_MNEMONIC_CMP &&
                Ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                Ops[0].mem.base == ZYDIS_REGISTER_RIP &&
                Ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                Ops[1].imm.value.s == 0 &&
                Ops[0].size == 64 )
            {
                UINT64 Target = ResolveMemOp( &Instr, &Ops[0], Va );

                ZydisDecodedInstruction Next;
                ZydisDecodedOperand NOps[ZYDIS_MAX_OPERAND_COUNT];
                if ( ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )( Va + Instr.length ), 16, &Next, NOps ) ) &&
                    Next.mnemonic == ZYDIS_MNEMONIC_JNZ )
                {
                    if ( ( UINT64* )Target == MaxDataSize )
                        Log( "Offsets: MaxDataSize cross-check passed" );
                    else
                        LogWarn( "Offsets: MaxDataSize cross-check mismatch ({} vs {})", Target, ( UINT64 )MaxDataSize );
                    break;
                }
            }

            Prev = Instr;
            Va += Instr.length;
        }
    }

    // Locate the EX_TIMER offset inside the PG context block by finding the MOV [Rxx+disp], RAX
    // that immediately follows the ExAllocateTimer call in the PG init path...
    //
    static NTSTATUS ResolveTimerContextOffset( ZydisDecoder* Decoder, UINT64 TextStart, UINT64 TextEnd )
    {
        UINT64 AddrExAllocateTimer = GetRoutine( L"ExAllocateTimer" );
        if ( !AddrExAllocateTimer )
        {
            LogError( "Offsets: ExAllocateTimer not found" );
            return STATUS_NOT_FOUND;
        }

        for ( UINT64 Va = TextStart; Va < TextEnd; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Va, TextEnd - Va, &Instr, Ops ) ) )
            {
                Va++; continue;
            }

            if ( Instr.mnemonic == ZYDIS_MNEMONIC_CALL &&
                Ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                Ops[0].mem.base == ZYDIS_REGISTER_RIP &&
                *( UINT64* )ResolveMemOp( &Instr, &Ops[0], Va ) == AddrExAllocateTimer )
            {
                UINT64 Next = Va + Instr.length;
                UINT64 Limit = Next + 48;
                if ( Limit > TextEnd ) Limit = TextEnd;

                while ( Next < Limit )
                {
                    ZydisDecodedInstruction Store;
                    ZydisDecodedOperand SOps[ZYDIS_MAX_OPERAND_COUNT];

                    if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Next, Limit - Next, &Store, SOps ) ) )
                        break;

                    if ( Store.mnemonic == ZYDIS_MNEMONIC_MOV &&
                        SOps[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        SOps[0].mem.disp.has_displacement &&
                        SOps[0].mem.disp.value > 0 &&
                        SOps[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        SOps[1].reg.value == ZYDIS_REGISTER_RAX )
                    {
                        Timer = ( UINT64 )SOps[0].mem.disp.value;
                        Log( "Offsets: TimerContextOffset -> {}", Timer );
                        return STATUS_SUCCESS;
                    }

                    Next += Store.length;
                }
            }

            Va += Instr.length;
        }

        LogError( "Offsets: timer context offset not found" );
        return STATUS_NOT_FOUND;
    }

    /// <summary>
    /// Resolves all kernel offsets used by the driver.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Init( )
    {
        Util::DriverInfo NtInfo{};
        if ( !Util::QueryDriver( "ntoskrnl.exe", &NtInfo ) )
        {
            LogError( "Offsets: ntoskrnl not found" );
            return STATUS_NOT_FOUND;
        }

        UINT64 TextStart = 0, TextSize = 0;
        if ( !FindTextSection( NtInfo.Base, &TextStart, &TextSize ) )
        {
            LogError( "Offsets: .text not found" );
            return STATUS_NOT_FOUND;
        }

        UINT64 TextEnd = TextStart + TextSize;

        ZydisDecoder Decoder;
        ZydisDecoderInit( &Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64 );

        NTSTATUS Status = ResolveKiFilterFiberContext( &Decoder, TextStart, TextEnd );
        if ( !NT_SUCCESS( Status ) )
            return Status;

        Status = ExtractGlobalsFromKiFilterFiberContext( &Decoder );
        if ( !NT_SUCCESS( Status ) )
            return Status;

        Status = ResolveTimerContextOffset( &Decoder, TextStart, TextEnd );
        if ( !NT_SUCCESS( Status ) )
            return Status;

        CrossCheckMaxDataSize( &Decoder, TextStart, TextEnd );

        return STATUS_SUCCESS;
    }

}
