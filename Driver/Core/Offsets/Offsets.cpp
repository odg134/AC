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

    static bool FindNamedSection( PVOID Base, const char* Name, UINT64* OutStart, UINT64* OutSize )
    {
        auto* Dos = (PIMAGE_DOS_HEADER)Base;
        if ( Dos->e_magic != IMAGE_DOS_SIGNATURE )
            return false;

        auto* Nt = (PIMAGE_NT_HEADERS)( (PUCHAR)Base + Dos->e_lfanew );
        if ( Nt->Signature != IMAGE_NT_SIGNATURE )
            return false;

        PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION( Nt );
        SIZE_T NameLen = 0;
        while ( Name[ NameLen ] ) ++NameLen;

        for ( USHORT i = 0; i < Nt->FileHeader.NumberOfSections; ++i )
        {
            if ( RtlCompareMemory( Sec[ i ].Name, Name, NameLen ) == NameLen &&
                 ( NameLen == 8 || Sec[ i ].Name[ NameLen ] == '\0' ) )
            {
                *OutStart = ( UINT64 )Base + Sec[ i ].VirtualAddress;
                *OutSize  = Sec[ i ].Misc.VirtualSize;
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

    // Count CMP [RIP+x], 0 instructions in the window [Va, Va+WindowSize).
    // Used to score KiFilterFiberContext candidates — the real function has 3+.
    //
    static int CountCmpRipZero( ZydisDecoder* Decoder, UINT64 Va, UINT64 WindowSize )
    {
        UINT64 End = Va + WindowSize;
        int Score = 0;

        while ( Va < End )
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
                ++Score;
            }

            Va += Instr.length;
        }

        return Score;
    }

    // Scan one section for KiFilterFiberContext using a score-based approach.
    // Finds all callers of KdDisableDebugger (direct E8 rel32 OR indirect FF15 IAT),
    // then picks the one with the most CMP [RIP+x],0 instructions in its body.
    // Updates BestScore and BestVa when a better candidate is found.
    //
    static void ScanKiFilterFiberContext(
        ZydisDecoder* Decoder, UINT64 SecStart, UINT64 SecEnd,
        UINT64 AddrKdDisableDebugger, int* BestScore, UINT64* BestVa )
    {
        for ( UINT64 Va = SecStart; Va < SecEnd; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Va, SecEnd - Va, &Instr, Ops ) ) )
            {
                Va++; continue;
            }

            if ( Instr.mnemonic == ZYDIS_MNEMONIC_CALL )
            {
                UINT64 CallTarget = 0;

                if ( Ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE )
                {
                    // Direct CALL rel32 (E8) — ntoskrnl self-call
                    ZydisCalcAbsoluteAddress( &Instr, &Ops[0], Va, &CallTarget );
                }
                else if ( Ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                          Ops[0].mem.base == ZYDIS_REGISTER_RIP )
                {
                    // Indirect CALL [RIP+x] (FF 15) — IAT import
                    UINT64 Slot = 0;
                    ZydisCalcAbsoluteAddress( &Instr, &Ops[0], Va, &Slot );
                    CallTarget = *reinterpret_cast<UINT64*>( Slot );
                }

                if ( CallTarget == AddrKdDisableDebugger )
                {
                    UINT64 BodyStart = Va + Instr.length;
                    UINT64 BodyEnd   = BodyStart + 0x500;
                    if ( BodyEnd > SecEnd ) BodyEnd = SecEnd;

                    int Score = CountCmpRipZero( Decoder, BodyStart, BodyEnd - BodyStart );
                    if ( Score > *BestScore )
                    {
                        *BestScore = Score;
                        *BestVa    = Va;
                    }
                }
            }

            Va += Instr.length;
        }
    }

    static NTSTATUS ResolveKiFilterFiberContext(
        ZydisDecoder* Decoder,
        UINT64 TextStart, UINT64 TextEnd,
        UINT64 PageStart, UINT64 PageEnd )
    {
        UINT64 AddrKdDisableDebugger = GetRoutine( L"KdDisableDebugger" );
        if ( !AddrKdDisableDebugger )
        {
            LogError( "Offsets: KdDisableDebugger not found" );
            return STATUS_NOT_FOUND;
        }

        int    BestScore = 0;
        UINT64 BestVa    = 0;

        ScanKiFilterFiberContext( Decoder, TextStart, TextEnd, AddrKdDisableDebugger, &BestScore, &BestVa );
        if ( PageStart )
            ScanKiFilterFiberContext( Decoder, PageStart, PageEnd, AddrKdDisableDebugger, &BestScore, &BestVa );

        // KiFilterFiberContext contains the 3 CMP [RIP+x],0 checks extracted by
        // ExtractGlobalsFromKiFilterFiberContext — require at least 2 as a sanity gate.
        //
        if ( BestScore >= 2 )
        {
            KiFilterFiberContext = BestVa;
            Log( "Offsets: KiFilterFiberContext -> {} (score={})", BestVa, BestScore );
            return STATUS_SUCCESS;
        }

        LogError( "Offsets: KiFilterFiberContext not found (best score={})", BestScore );
        return STATUS_NOT_FOUND;
    }

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

    static void CrossCheckMaxDataSize( ZydisDecoder* Decoder, UINT64 SecStart, UINT64 SecEnd )
    {
        ZydisDecodedInstruction Prev{};

        for ( UINT64 Va = SecStart; Va < SecEnd; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Va, SecEnd - Va, &Instr, Ops ) ) )
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

    // Scan one section for ExAllocateTimer callers. Returns true on first match and
    // sets Timer to the displacement of the MOV [Rx+disp],RAX that follows the call.
    //
    static bool ScanTimerContextOffset(
        ZydisDecoder* Decoder, UINT64 SecStart, UINT64 SecEnd, UINT64 AddrExAllocateTimer )
    {
        for ( UINT64 Va = SecStart; Va < SecEnd; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Va, SecEnd - Va, &Instr, Ops ) ) )
            {
                Va++; continue;
            }

            if ( Instr.mnemonic == ZYDIS_MNEMONIC_CALL )
            {
                UINT64 CallTarget = 0;

                if ( Ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE )
                {
                    ZydisCalcAbsoluteAddress( &Instr, &Ops[0], Va, &CallTarget );
                }
                else if ( Ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                          Ops[0].mem.base == ZYDIS_REGISTER_RIP )
                {
                    UINT64 Slot = 0;
                    ZydisCalcAbsoluteAddress( &Instr, &Ops[0], Va, &Slot );
                    CallTarget = *reinterpret_cast<UINT64*>( Slot );
                }

                if ( CallTarget == AddrExAllocateTimer )
                {
                    UINT64 Next  = Va + Instr.length;
                    UINT64 Limit = Next + 48;
                    if ( Limit > SecEnd ) Limit = SecEnd;

                    while ( Next < Limit )
                    {
                        ZydisDecodedInstruction Store;
                        ZydisDecodedOperand SOps[ZYDIS_MAX_OPERAND_COUNT];

                        if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Next, Limit - Next, &Store, SOps ) ) )
                            break;

                        // Require disp > 0x100 to target the PG context timer field
                        // (small displacements like 0x8 are unrelated local struct stores).
                        if ( Store.mnemonic == ZYDIS_MNEMONIC_MOV &&
                            SOps[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                            SOps[0].mem.base != ZYDIS_REGISTER_RIP &&
                            SOps[0].mem.disp.has_displacement &&
                            SOps[0].mem.disp.value > 0x100 &&
                            SOps[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                            SOps[1].reg.value == ZYDIS_REGISTER_RAX )
                        {
                            Timer = ( UINT64 )SOps[0].mem.disp.value;
                            Log( "Offsets: TimerContextOffset -> {}", Timer );
                            return true;
                        }

                        Next += Store.length;
                    }
                }
            }

            Va += Instr.length;
        }
        return false;
    }

    static NTSTATUS ResolveTimerContextOffset(
        ZydisDecoder* Decoder,
        UINT64 TextStart, UINT64 TextEnd,
        UINT64 PageStart, UINT64 PageEnd )
    {
        UINT64 AddrExAllocateTimer = GetRoutine( L"ExAllocateTimer" );
        if ( !AddrExAllocateTimer )
        {
            LogError( "Offsets: ExAllocateTimer not found" );
            return STATUS_NOT_FOUND;
        }

        if ( ScanTimerContextOffset( Decoder, TextStart, TextEnd, AddrExAllocateTimer ) )
            return STATUS_SUCCESS;

        if ( PageStart && ScanTimerContextOffset( Decoder, PageStart, PageEnd, AddrExAllocateTimer ) )
            return STATUS_SUCCESS;

        LogError( "Offsets: timer context offset not found" );
        return STATUS_NOT_FOUND;
    }

    // Scan one section for the WmipGetSMBiosTableData anchor sequence and extract
    // the two RIP-relative globals from the lookback window.
    //
    static bool ScanSmbiosPattern(
        ZydisDecoder* Decoder, UINT64 SecStart, UINT64 SecEnd )
    {
        for ( UINT64 Va = SecStart; Va < SecEnd; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Va, SecEnd - Va, &Instr, Ops ) ) )
            {
                Va++; continue;
            }

            // Match: TEST RCX, RCX
            if ( Instr.mnemonic != ZYDIS_MNEMONIC_TEST ||
                 Ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER || Ops[0].reg.value != ZYDIS_REGISTER_RCX ||
                 Ops[1].type != ZYDIS_OPERAND_TYPE_REGISTER || Ops[1].reg.value != ZYDIS_REGISTER_RCX )
            {
                Va += Instr.length; continue;
            }

            UINT64 N = Va + Instr.length;

            ZydisDecodedInstruction I2, I3, I4;
            ZydisDecodedOperand     O2[ZYDIS_MAX_OPERAND_COUNT],
                                    O3[ZYDIS_MAX_OPERAND_COUNT],
                                    O4[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )N, SecEnd - N, &I2, O2 ) ) ||
                 I2.mnemonic != ZYDIS_MNEMONIC_JZ )
            { Va += Instr.length; continue; }

            N += I2.length;

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )N, SecEnd - N, &I3, O3 ) ) ||
                 I3.mnemonic != ZYDIS_MNEMONIC_MOV ||
                 O3[0].type != ZYDIS_OPERAND_TYPE_REGISTER || O3[0].reg.value != ZYDIS_REGISTER_EDX ||
                 O3[1].type != ZYDIS_OPERAND_TYPE_REGISTER || O3[1].reg.value != ZYDIS_REGISTER_EAX )
            { Va += Instr.length; continue; }

            N += I3.length;

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )N, SecEnd - N, &I4, O4 ) ) ||
                 I4.mnemonic != ZYDIS_MNEMONIC_MOV ||
                 O4[0].type != ZYDIS_OPERAND_TYPE_REGISTER || O4[0].reg.value != ZYDIS_REGISTER_R8D ||
                 O4[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || O4[1].imm.value.u != 4 )
            { Va += Instr.length; continue; }

            UINT64 Window = ( Va > SecStart + 80 ) ? Va - 80 : SecStart;
            UINT64 EaxGlobal = 0;
            UINT64 RcxGlobal = 0;

            for ( UINT64 V2 = Window; V2 < Va; )
            {
                ZydisDecodedInstruction Ix;
                ZydisDecodedOperand     Ox[ZYDIS_MAX_OPERAND_COUNT];

                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )V2, Va - V2, &Ix, Ox ) ) )
                { V2++; continue; }

                if ( Ix.mnemonic == ZYDIS_MNEMONIC_MOV &&
                     Ox[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                     Ox[0].reg.value == ZYDIS_REGISTER_EAX &&
                     Ox[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                     Ox[1].mem.base == ZYDIS_REGISTER_RIP )
                {
                    ZydisCalcAbsoluteAddress( &Ix, &Ox[1], V2, &EaxGlobal );
                }

                if ( Ix.mnemonic == ZYDIS_MNEMONIC_MOV &&
                     Ox[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                     Ox[0].reg.value == ZYDIS_REGISTER_RCX &&
                     Ox[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                     Ox[1].mem.base == ZYDIS_REGISTER_RIP )
                {
                    ZydisCalcAbsoluteAddress( &Ix, &Ox[1], V2, &RcxGlobal );
                }

                V2 += Ix.length;
            }

            if ( !EaxGlobal || !RcxGlobal )
            { Va += Instr.length; continue; }

            WmipSMBiosTableLength           = ( UINT32* )EaxGlobal;
            WmipSMBiosTablePhysicalAddress  = ( UINT64* )RcxGlobal;
            Log( "Offsets: WmipSMBiosTableLength -> {}", EaxGlobal );
            Log( "Offsets: WmipSMBiosTablePhysicalAddress -> {}", RcxGlobal );
            return true;
        }
        return false;
    }

    // Alternative SMBIOS pattern for builds where the TEST RCX,RCX/JZ/MOV anchor
    // does not appear: scan for adjacent RIP-relative stores where a 64-bit store
    // (physical address) is within 32 bytes of a 32-bit store (length), preceded by
    // a null-check branch on the 64-bit register. Reliable because no other pair of
    // neighboring globals has this exact type signature in the SMBIOS init path.
    //
    static bool ScanSmbiosStorePairs( ZydisDecoder* Decoder, UINT64 SecStart, UINT64 SecEnd )
    {
        UINT64 LastStore64Va  = 0;
        UINT64 LastStore64Gbl = 0;
        ZydisRegister LastStore64Reg = ZYDIS_REGISTER_NONE;

        for ( UINT64 Va = SecStart; Va < SecEnd; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Va, SecEnd - Va, &Instr, Ops ) ) )
            {
                Va++; continue;
            }

            // MOV [RIP+x], reg64
            if ( Instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                 Ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 Ops[0].mem.base == ZYDIS_REGISTER_RIP &&
                 Ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                 Ops[0].size == 64 )
            {
                LastStore64Va  = Va;
                LastStore64Gbl = ResolveMemOp( &Instr, &Ops[0], Va );
                LastStore64Reg = Ops[1].reg.value;
            }

            // MOV [RIP+y], reg32  within 32 bytes of a prior 64-bit store
            else if ( Instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                      Ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                      Ops[0].mem.base == ZYDIS_REGISTER_RIP &&
                      Ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                      Ops[0].size == 32 &&
                      LastStore64Va != 0 && Va - LastStore64Va <= 32 )
            {
                UINT64 LenGlobal = ResolveMemOp( &Instr, &Ops[0], Va );

                // Verify that the 64-bit register was null-checked somewhere in the
                // 120 bytes before the 64-bit store (TEST reg,reg or CMP reg,0).
                bool FoundCheck = false;
                UINT64 ChkStart = ( LastStore64Va > SecStart + 120 ) ? LastStore64Va - 120 : SecStart;
                for ( UINT64 Cv = ChkStart; Cv < LastStore64Va && !FoundCheck; )
                {
                    ZydisDecodedInstruction Ci;
                    ZydisDecodedOperand     Co[ZYDIS_MAX_OPERAND_COUNT];
                    if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Cv, LastStore64Va - Cv, &Ci, Co ) ) )
                    { Cv++; continue; }

                    if ( ( Ci.mnemonic == ZYDIS_MNEMONIC_TEST || Ci.mnemonic == ZYDIS_MNEMONIC_CMP ) &&
                         Co[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                         Co[0].reg.value == LastStore64Reg )
                        FoundCheck = true;

                    Cv += Ci.length;
                }

                if ( FoundCheck )
                {
                    WmipSMBiosTablePhysicalAddress = ( UINT64* )LastStore64Gbl;
                    WmipSMBiosTableLength          = ( UINT32* )LenGlobal;
                    Log( "Offsets: WmipSMBiosTablePhysicalAddress (alt) -> {}", LastStore64Gbl );
                    Log( "Offsets: WmipSMBiosTableLength (alt) -> {}", LenGlobal );
                    return true;
                }
            }
            else
            {
                // Reset tracker on any control-flow instruction so we only match
                // stores within the same basic block.
                if ( Instr.mnemonic == ZYDIS_MNEMONIC_CALL ||
                     Instr.mnemonic == ZYDIS_MNEMONIC_RET  ||
                     Instr.mnemonic == ZYDIS_MNEMONIC_JMP )
                {
                    LastStore64Va = 0;
                }
            }

            Va += Instr.length;
        }
        return false;
    }

    static NTSTATUS ResolveSmbiosGlobals(
        ZydisDecoder* Decoder,
        UINT64 TextStart, UINT64 TextEnd,
        UINT64 PageStart, UINT64 PageEnd )
    {
        if ( ScanSmbiosPattern( Decoder, TextStart, TextEnd ) )
            return STATUS_SUCCESS;

        if ( PageStart && ScanSmbiosPattern( Decoder, PageStart, PageEnd ) )
            return STATUS_SUCCESS;

        if ( ScanSmbiosStorePairs( Decoder, TextStart, TextEnd ) )
            return STATUS_SUCCESS;

        if ( PageStart && ScanSmbiosStorePairs( Decoder, PageStart, PageEnd ) )
            return STATUS_SUCCESS;

        LogError( "Offsets: SMBIOS globals not found" );
        return STATUS_NOT_FOUND;
    }

    // Locate ndisMiniportList by finding the distinctive three-instruction sequence in
    // ndisRemoveMiniportFromGlobalList that appears immediately after the
    // KeAcquireSpinLockRaiseToDpc call:
    //
    //   MOVZX r8d, al               ; save old IRQL in r8b
    //   LEA   any_reg, [RIP + rel32] ; <-- address of ndisMiniportList (any dest reg)
    //   MOV   rdx, [same_reg]       ; dereference to head of list
    //   TEST  rdx, rdx
    //
    static NTSTATUS ResolveNdisMiniportList(
        ZydisDecoder* Decoder, UINT64 SecStart, UINT64 SecEnd )
    {
        for ( UINT64 Va = SecStart; Va < SecEnd; )
        {
            ZydisDecodedInstruction I1;
            ZydisDecodedOperand O1[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)Va, SecEnd - Va, &I1, O1 ) ) )
            {
                Va++; continue;
            }

            // MOVZX r8d, al
            if ( I1.mnemonic != ZYDIS_MNEMONIC_MOVZX ||
                 O1[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                 O1[0].reg.value != ZYDIS_REGISTER_R8D ||
                 O1[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                 O1[1].reg.value != ZYDIS_REGISTER_AL )
            {
                Va += I1.length; continue;
            }

            UINT64 N = Va + I1.length;

            ZydisDecodedInstruction I2, I3, I4;
            ZydisDecodedOperand     O2[ZYDIS_MAX_OPERAND_COUNT],
                                    O3[ZYDIS_MAX_OPERAND_COUNT],
                                    O4[ZYDIS_MAX_OPERAND_COUNT];

            // LEA any_reg64, [RIP + rel32]
            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)N, SecEnd - N, &I2, O2 ) ) ||
                 I2.mnemonic != ZYDIS_MNEMONIC_LEA ||
                 O2[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                 O2[0].size != 64 ||
                 O2[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                 O2[1].mem.base != ZYDIS_REGISTER_RIP )
            {
                Va += I1.length; continue;
            }

            auto LeaDestReg = O2[0].reg.value;
            N += I2.length;

            // Strategy 1 (26100/28000): MOV rdx, [lea_dest_reg] / TEST rdx, rdx
            bool S1 = false;
            if ( ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)N, SecEnd - N, &I3, O3 ) ) &&
                 I3.mnemonic == ZYDIS_MNEMONIC_MOV &&
                 O3[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                 O3[0].reg.value == ZYDIS_REGISTER_RDX &&
                 O3[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 O3[1].mem.base == LeaDestReg )
            {
                UINT64 N4 = N + I3.length;
                if ( ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)N4, SecEnd - N4, &I4, O4 ) ) &&
                     I4.mnemonic == ZYDIS_MNEMONIC_TEST &&
                     O4[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                     O4[0].reg.value == ZYDIS_REGISTER_RDX &&
                     O4[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                     O4[1].reg.value == ZYDIS_REGISTER_RDX )
                {
                    S1 = true;
                }
            }

            // Strategy 2 (22000/22621/tiny11): within the next 5 instructions after the
            // LEA, find any CMP or TEST that references the LEA destination register.
            // This matches the empty-list check: CMP [head_ptr], lea_reg or TEST lea_reg.
            //
            bool S2 = false;
            if ( !S1 )
            {
                UINT64 Scan = N;
                for ( int Step = 0; Step < 5 && Scan < SecEnd && !S2; ++Step )
                {
                    ZydisDecodedInstruction Sx;
                    ZydisDecodedOperand Ox[ZYDIS_MAX_OPERAND_COUNT];
                    if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)Scan, SecEnd - Scan, &Sx, Ox ) ) )
                        break;

                    if ( Sx.mnemonic == ZYDIS_MNEMONIC_CMP || Sx.mnemonic == ZYDIS_MNEMONIC_TEST )
                    {
                        for ( ULONG oi = 0; oi < Sx.operand_count; ++oi )
                        {
                            if ( Ox[oi].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                 Ox[oi].reg.value == LeaDestReg )
                            {
                                S2 = true; break;
                            }
                        }
                    }
                    Scan += Sx.length;
                }
            }

            if ( !S1 && !S2 )
            {
                Va += I1.length; continue;
            }

            ZydisCalcAbsoluteAddress( &I2, &O2[1], Va + I1.length, &NdisMiniportList );
            Log( "Offsets: NdisMiniportList -> {} ({})", NdisMiniportList, S1 ? "S1" : "S2" );
            return STATUS_SUCCESS;
        }

        LogError( "Offsets: NdisMiniportList pattern not found" );
        return STATUS_NOT_FOUND;
    }

    static NTSTATUS ResolveNdisStructOffsets(
        ZydisDecoder* Decoder, UINT64 SecStart, UINT64 SecEnd )
    {
        // Find the self-referential MOV to extract NdisMpNextOffset.
        // Broadened displacement range to cover all known builds (0 to 0x2000).
        //
        bool FoundNext = false;
        for ( UINT64 Va = SecStart; Va < SecEnd && !FoundNext; )
        {
            ZydisDecodedInstruction I1;
            ZydisDecodedOperand O1[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)Va, SecEnd - Va, &I1, O1 ) ) )
            {
                Va++; continue;
            }

            // MOV reg64, [same_reg64 + disp]  in range 0x8 – 0x2000
            if ( I1.mnemonic == ZYDIS_MNEMONIC_MOV &&
                 O1[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                 O1[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 O1[1].mem.base == O1[0].reg.value &&
                 O1[1].mem.disp.has_displacement &&
                 O1[1].mem.disp.value >= 0x8 &&
                 O1[1].mem.disp.value <= 0x2000 &&
                 O1[0].size == 64 )
            {
                UINT64 N = Va + I1.length;
                auto   Reg  = O1[0].reg.value;
                UINT64 Disp = (UINT64)O1[1].mem.disp.value;

                ZydisDecodedInstruction I2, I3;
                ZydisDecodedOperand     O2[ZYDIS_MAX_OPERAND_COUNT],
                                        O3[ZYDIS_MAX_OPERAND_COUNT];

                // TEST same_reg, same_reg
                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)N, SecEnd - N, &I2, O2 ) ) ||
                     I2.mnemonic != ZYDIS_MNEMONIC_TEST ||
                     O2[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                     O2[0].reg.value != Reg ||
                     O2[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                     O2[1].reg.value != Reg )
                {
                    Va += I1.length; continue;
                }

                N += I2.length;

                // JNZ backward into the loop
                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)N, SecEnd - N, &I3, O3 ) ) ||
                     I3.mnemonic != ZYDIS_MNEMONIC_JNZ )
                {
                    Va += I1.length; continue;
                }

                UINT64 Target = 0;
                ZydisCalcAbsoluteAddress( &I3, &O3[0], N, &Target );
                if ( Target >= Va )
                {
                    Va += I1.length; continue;
                }

                NdisMpNextOffset = static_cast< UINT32 >( Disp );
                Log( "Offsets: NdisMpNextOffset -> {}", Disp );
                FoundNext = true;
            }

            Va += I1.length;
        }

        if ( !FoundNext )
        {
            LogError( "Offsets: NdisMpNextOffset pattern not found" );
            return STATUS_NOT_FOUND;
        }

        // Find ndisIfUpdateCurrentMacAddress by its unique two-instruction prologue
        // (after the spinlock acquire):
        //
        //   MOVZX esi, word ptr [rdi]   ; 0F B7 37
        //   MOVZX ebp, al               ; 0F B6 E8
        //
        bool FoundCurrentMac   = false;
        bool FoundPermanentMac = false;

        for ( UINT64 Va = SecStart; Va < SecEnd && !( FoundCurrentMac && FoundPermanentMac ); )
        {
            ZydisDecodedInstruction I1;
            ZydisDecodedOperand O1[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)Va, SecEnd - Va, &I1, O1 ) ) )
            {
                Va++; continue;
            }

            // MOVZX esi, word ptr [rdi]
            if ( I1.mnemonic != ZYDIS_MNEMONIC_MOVZX ||
                 O1[0].type  != ZYDIS_OPERAND_TYPE_REGISTER ||
                 O1[0].reg.value != ZYDIS_REGISTER_ESI ||
                 O1[1].type  != ZYDIS_OPERAND_TYPE_MEMORY ||
                 O1[1].mem.base != ZYDIS_REGISTER_RDI ||
                 O1[1].mem.disp.value != 0 )
            {
                Va += I1.length; continue;
            }

            UINT64 N = Va + I1.length;

            ZydisDecodedInstruction I2;
            ZydisDecodedOperand O2[ZYDIS_MAX_OPERAND_COUNT];

            // MOVZX ebp, al
            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)N, SecEnd - N, &I2, O2 ) ) ||
                 I2.mnemonic != ZYDIS_MNEMONIC_MOVZX ||
                 O2[0].type  != ZYDIS_OPERAND_TYPE_REGISTER ||
                 O2[0].reg.value != ZYDIS_REGISTER_EBP ||
                 O2[1].type  != ZYDIS_OPERAND_TYPE_REGISTER ||
                 O2[1].reg.value != ZYDIS_REGISTER_AL )
            {
                Va += I1.length; continue;
            }

            // Scan up to 0x200 bytes forward from this prologue for CMP [reg+disp], SI16
            // where 0x300 < disp < 0x900 (covers 0x464 on 26100/28000 and 0x6ba on 22000/22621).
            //
            UINT64 Limit = N + I2.length + 0x200;
            if ( Limit > SecEnd ) Limit = SecEnd;
            UINT64 Scan = N + I2.length;

            while ( Scan < Limit )
            {
                ZydisDecodedInstruction Ix;
                ZydisDecodedOperand Ox[ZYDIS_MAX_OPERAND_COUNT];

                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)Scan, Limit - Scan, &Ix, Ox ) ) )
                    break;

                if ( Ix.mnemonic == ZYDIS_MNEMONIC_CMP &&
                     Ox[0].type  == ZYDIS_OPERAND_TYPE_MEMORY &&
                     Ox[0].mem.base != ZYDIS_REGISTER_RIP &&
                     Ox[0].mem.disp.has_displacement &&
                     Ox[0].mem.disp.value > 0x300 &&
                     Ox[0].mem.disp.value < 0x900 &&
                     Ox[1].type  == ZYDIS_OPERAND_TYPE_REGISTER &&
                     Ox[1].size  == 16 )
                {
                    UINT64 Disp = (UINT64)Ox[0].mem.disp.value;

                    if ( !FoundCurrentMac )
                    {
                        NdisIfCurrentMacLen = static_cast< UINT32 >( Disp );
                        NdisIfCurrentMac    = static_cast< UINT32 >( Disp + 2 );
                        Log( "Offsets: NdisIfCurrentMacLen -> {}", Disp );
                        Log( "Offsets: NdisIfCurrentMac -> {}", Disp + 2 );
                        FoundCurrentMac = true;
                    }
                    else if ( !FoundPermanentMac && Disp != NdisIfCurrentMacLen )
                    {
                        NdisIfPermMacLen = static_cast< UINT32 >( Disp );
                        NdisIfPermMac    = static_cast< UINT32 >( Disp + 2 );
                        Log( "Offsets: NdisIfPermMacLen -> {}", Disp );
                        Log( "Offsets: NdisIfPermMac -> {}", Disp + 2 );
                        FoundPermanentMac = true;
                    }

                    if ( FoundCurrentMac && FoundPermanentMac )
                        break;
                }

                Scan += Ix.length;
            }

            Va += I1.length;
        }

        if ( !FoundCurrentMac || !FoundPermanentMac )
        {
            LogError( "Offsets: NDIS MAC field offsets not fully resolved ({}, {})",
                      FoundCurrentMac, FoundPermanentMac );
            return STATUS_NOT_FOUND;
        }

        // Derive NdisMpIfBlockOffset: find MOV reg64, [rcx + disp] (broadened range)
        // followed within 10 bytes by access to [same_reg + NdisIfCurrentMacLen].
        //
        for ( UINT64 Va = SecStart; Va < SecEnd; )
        {
            ZydisDecodedInstruction I1;
            ZydisDecodedOperand O1[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)Va, SecEnd - Va, &I1, O1 ) ) )
            {
                Va++; continue;
            }

            if ( I1.mnemonic == ZYDIS_MNEMONIC_MOV &&
                 O1[0].type  == ZYDIS_OPERAND_TYPE_REGISTER &&
                 O1[0].size  == 64 &&
                 O1[1].type  == ZYDIS_OPERAND_TYPE_MEMORY &&
                 O1[1].mem.base == ZYDIS_REGISTER_RCX &&
                 O1[1].mem.disp.has_displacement &&
                 O1[1].mem.disp.value > 0 &&
                 O1[1].mem.disp.value < 0x2000 )
            {
                auto   IfReg = O1[0].reg.value;
                UINT64 Disp  = (UINT64)O1[1].mem.disp.value;
                UINT64 N     = Va + I1.length;
                UINT64 Limit = N + 10;
                if ( Limit > SecEnd ) Limit = SecEnd;

                while ( N < Limit )
                {
                    ZydisDecodedInstruction Ix;
                    ZydisDecodedOperand Ox[ZYDIS_MAX_OPERAND_COUNT];

                    if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)N, Limit - N, &Ix, Ox ) ) )
                        break;

                    if ( Ix.mnemonic == ZYDIS_MNEMONIC_MOVZX &&
                         Ox[1].type  == ZYDIS_OPERAND_TYPE_MEMORY &&
                         Ox[1].mem.base == IfReg &&
                         Ox[1].mem.disp.has_displacement &&
                         (UINT64)Ox[1].mem.disp.value == NdisIfCurrentMacLen )
                    {
                        NdisMpIfBlockOffset = static_cast< UINT32 >( Disp );
                        Log( "Offsets: NdisMpIfBlockOffset -> {}", Disp );
                        return STATUS_SUCCESS;
                    }

                    N += Ix.length;
                }
            }

            Va += I1.length;
        }

        LogError( "Offsets: NdisMpIfBlockOffset pattern not found" );
        return STATUS_NOT_FOUND;
    }

    // Resolve MmUnloadedDrivers and MmLastUnloadedDriver by scanning for the
    // characteristic list-walk in MmLocateUnloadedDriver:
    //
    //   MOV EAX, [RIP+MmLastUnloadedDriver]   ; load ULONG index
    //   ...
    //   IMUL r64, r64/rax, 0x28 (or 0x2C)    ; stride = sizeof(MM_UNLOADED_DRIVER)
    //   ...
    //   LEA/ADD rcx, [RIP+MmUnloadedDrivers]   ; base of array
    //
    static NTSTATUS ResolveMmUnloadedDrivers( ZydisDecoder* Decoder, UINT64 SecStart, UINT64 SecEnd )
    {
        // Try direct export first (available pre-Win10).
        UINT64 Exp = GetRoutine( L"MmUnloadedDrivers" );
        if ( Exp )
        {
            MmUnloadedDrivers = reinterpret_cast< PVOID* >( Exp );
            Log( "Offsets: MmUnloadedDrivers (export) -> {}", Exp );

            UINT64 ExpLast = GetRoutine( L"MmLastUnloadedDriver" );
            if ( ExpLast )
            {
                MmLastUnloadedDriver = reinterpret_cast< ULONG* >( ExpLast );
                Log( "Offsets: MmLastUnloadedDriver (export) -> {}", ExpLast );
                return STATUS_SUCCESS;
            }
        }

        // Pattern scan: find IMUL r64, r64, 0x28 (MM_UNLOADED_DRIVER stride)
        // with a preceding RIP-relative ULONG load (MmLastUnloadedDriver) and
        // a following RIP-relative pointer load/LEA (MmUnloadedDrivers).
        //
        for ( UINT64 Va = SecStart; Va < SecEnd; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Va, SecEnd - Va, &Instr, Ops ) ) )
            {
                Va++; continue;
            }

            // IMUL reg64, reg64, imm  where imm is 0x28 or 0x2C
            if ( Instr.mnemonic == ZYDIS_MNEMONIC_IMUL &&
                 Ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                 Ops[0].size == 64 &&
                 Ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                 ( Ops[2].imm.value.u == 0x28 || Ops[2].imm.value.u == 0x2C ) )
            {
                // Scan backward up to 64 bytes for MOV r32, [RIP+x] (the last-driver index)
                UINT64 WinStart = ( Va > SecStart + 64 ) ? Va - 64 : SecStart;
                UINT64 LastDrvGlobal = 0;

                for ( UINT64 V2 = WinStart; V2 < Va; )
                {
                    ZydisDecodedInstruction Bk;
                    ZydisDecodedOperand     Bo[ZYDIS_MAX_OPERAND_COUNT];
                    if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )V2, Va - V2, &Bk, Bo ) ) )
                    { V2++; continue; }

                    if ( Bk.mnemonic == ZYDIS_MNEMONIC_MOV &&
                         Bo[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                         ( Bo[0].size == 32 || Bo[0].size == 64 ) &&
                         Bo[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                         Bo[1].mem.base == ZYDIS_REGISTER_RIP )
                    {
                        ZydisCalcAbsoluteAddress( &Bk, &Bo[1], V2, &LastDrvGlobal );
                    }
                    V2 += Bk.length;
                }

                if ( !LastDrvGlobal )
                { Va += Instr.length; continue; }

                // Scan forward up to 48 bytes for LEA reg, [RIP+x] (the array base)
                UINT64 WinEnd   = Va + Instr.length;
                UINT64 ArrGlobal = 0;
                UINT64 FwdLimit = WinEnd + 48;
                if ( FwdLimit > SecEnd ) FwdLimit = SecEnd;

                for ( UINT64 V3 = WinEnd; V3 < FwdLimit; )
                {
                    ZydisDecodedInstruction Fw;
                    ZydisDecodedOperand     Fo[ZYDIS_MAX_OPERAND_COUNT];
                    if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )V3, FwdLimit - V3, &Fw, Fo ) ) )
                    { V3++; continue; }

                    if ( ( Fw.mnemonic == ZYDIS_MNEMONIC_LEA || Fw.mnemonic == ZYDIS_MNEMONIC_MOV ) &&
                         Fo[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                         Fo[0].size == 64 &&
                         Fo[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                         Fo[1].mem.base == ZYDIS_REGISTER_RIP )
                    {
                        ZydisCalcAbsoluteAddress( &Fw, &Fo[1], V3, &ArrGlobal );
                        break;
                    }
                    V3 += Fw.length;
                }

                if ( !ArrGlobal )
                { Va += Instr.length; continue; }

                MmUnloadedDrivers    = reinterpret_cast< PVOID* >( ArrGlobal );
                MmLastUnloadedDriver = reinterpret_cast< ULONG* >( LastDrvGlobal );
                Log( "Offsets: MmUnloadedDrivers -> {}", ArrGlobal );
                Log( "Offsets: MmLastUnloadedDriver -> {}", LastDrvGlobal );
                return STATUS_SUCCESS;
            }

            Va += Instr.length;
        }

        LogError( "Offsets: MmUnloadedDrivers not found" );
        return STATUS_NOT_FOUND;
    }

    // Resolve PiDDBCacheTable and PiDDBLock by finding call sites to
    // RtlLookupElementGenericTableAvl (exported) and extracting the LEA RCX,[RIP+x]
    // argument that immediately precedes the call (= PiDDBCacheTable).
    // PiDDBLock is found via ExAcquireResourceExclusiveLite calls near PiDDBCacheTable usage.
    //
    static NTSTATUS ResolvePiDDB( ZydisDecoder* Decoder, UINT64 SecStart, UINT64 SecEnd )
    {
        UINT64 AddrLookup = GetRoutine( L"RtlLookupElementGenericTableAvl" );
        if ( !AddrLookup )
        {
            LogWarn( "Offsets: RtlLookupElementGenericTableAvl not exported, skipping PiDDB" );
            return STATUS_NOT_FOUND;
        }

        UINT64 AddrAcquire = GetRoutine( L"ExAcquireResourceExclusiveLite" );

        for ( UINT64 Va = SecStart; Va < SecEnd; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Va, SecEnd - Va, &Instr, Ops ) ) )
            {
                Va++; continue;
            }

            // Find CALL [RIP+x] where the IAT slot holds AddrLookup
            if ( Instr.mnemonic == ZYDIS_MNEMONIC_CALL &&
                 Ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 Ops[0].mem.base == ZYDIS_REGISTER_RIP )
            {
                UINT64 Slot = ResolveMemOp( &Instr, &Ops[0], Va );
                if ( *( UINT64* )Slot != AddrLookup )
                {
                    Va += Instr.length; continue;
                }

                // Walk backward up to 24 bytes for LEA RCX, [RIP+PiDDBCacheTable]
                UINT64 WinStart = ( Va > SecStart + 24 ) ? Va - 24 : SecStart;
                UINT64 TableGlobal = 0;

                for ( UINT64 V2 = WinStart; V2 < Va; )
                {
                    ZydisDecodedInstruction Bk;
                    ZydisDecodedOperand     Bo[ZYDIS_MAX_OPERAND_COUNT];
                    if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )V2, Va - V2, &Bk, Bo ) ) )
                    { V2++; continue; }

                    if ( Bk.mnemonic == ZYDIS_MNEMONIC_LEA &&
                         Bo[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                         Bo[0].reg.value == ZYDIS_REGISTER_RCX &&
                         Bo[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                         Bo[1].mem.base == ZYDIS_REGISTER_RIP )
                    {
                        ZydisCalcAbsoluteAddress( &Bk, &Bo[1], V2, &TableGlobal );
                    }
                    V2 += Bk.length;
                }

                if ( !TableGlobal )
                { Va += Instr.length; continue; }

                PiDDBCacheTable = reinterpret_cast< PVOID >( TableGlobal );
                Log( "Offsets: PiDDBCacheTable -> {}", TableGlobal );

                // Find PiDDBLock: scan backward up to 200 bytes for
                // CALL [ExAcquireResourceExclusiveLite] with LEA RCX, [RIP+x] before it.
                if ( AddrAcquire )
                {
                    UINT64 LockWinStart = ( Va > SecStart + 200 ) ? Va - 200 : SecStart;

                    for ( UINT64 V3 = LockWinStart; V3 < Va; )
                    {
                        ZydisDecodedInstruction Ac;
                        ZydisDecodedOperand     Ao[ZYDIS_MAX_OPERAND_COUNT];
                        if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )V3, Va - V3, &Ac, Ao ) ) )
                        { V3++; continue; }

                        if ( Ac.mnemonic == ZYDIS_MNEMONIC_CALL &&
                             Ao[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                             Ao[0].mem.base == ZYDIS_REGISTER_RIP &&
                             *( UINT64* )ResolveMemOp( &Ac, &Ao[0], V3 ) == AddrAcquire )
                        {
                            UINT64 LockWin2 = ( V3 > SecStart + 16 ) ? V3 - 16 : SecStart;
                            for ( UINT64 V4 = LockWin2; V4 < V3; )
                            {
                                ZydisDecodedInstruction Lk;
                                ZydisDecodedOperand     Lo[ZYDIS_MAX_OPERAND_COUNT];
                                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )V4, V3 - V4, &Lk, Lo ) ) )
                                { V4++; continue; }

                                if ( Lk.mnemonic == ZYDIS_MNEMONIC_LEA &&
                                     Lo[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                     Lo[0].reg.value == ZYDIS_REGISTER_RCX &&
                                     Lo[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                                     Lo[1].mem.base == ZYDIS_REGISTER_RIP )
                                {
                                    UINT64 LockGlobal = 0;
                                    ZydisCalcAbsoluteAddress( &Lk, &Lo[1], V4, &LockGlobal );
                                    if ( LockGlobal != TableGlobal )
                                    {
                                        PiDDBLock = reinterpret_cast< PVOID >( LockGlobal );
                                        Log( "Offsets: PiDDBLock -> {}", LockGlobal );
                                    }
                                }
                                V4 += Lk.length;
                            }
                        }
                        V3 += Ac.length;
                    }
                }

                return STATUS_SUCCESS;
            }

            Va += Instr.length;
        }

        LogError( "Offsets: PiDDBCacheTable not found" );
        return STATUS_NOT_FOUND;
    }

    // Find EPROCESS.Protection offset by scanning PsIsProtectedProcess.
    // Pattern: MOVZX EAX, BYTE PTR [RCX + X]  where X in [0x200, 0x1000],
    // followed within 5 instructions by TEST/AND on AL/EAX against 0x07 or 0x01.
    //
    static NTSTATUS ResolveEprocessProtectionOffset( ZydisDecoder* Decoder )
    {
        UINT64 Fn = GetRoutine( L"PsIsProtectedProcess" );
        if ( !Fn )
        {
            LogWarn( "Offsets: PsIsProtectedProcess not exported" );
            return STATUS_NOT_FOUND;
        }

        constexpr UINT64 ScanLimit = 64;

        for ( UINT64 Va = Fn; Va < Fn + ScanLimit; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, reinterpret_cast< void* >( Va ),
                Fn + ScanLimit - Va, &Instr, Ops ) ) )
            {
                Va++; continue;
            }

            // MOVZX EAX, BYTE PTR [RCX + disp32]
            if ( Instr.mnemonic == ZYDIS_MNEMONIC_MOVZX &&
                 Ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                 Ops[0].reg.value == ZYDIS_REGISTER_EAX &&
                 Ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 Ops[1].mem.base == ZYDIS_REGISTER_RCX &&
                 Ops[1].mem.disp.has_displacement &&
                 Ops[1].size == 8 )
            {
                INT64 Disp = Ops[1].mem.disp.value;
                if ( Disp >= 0x200 && Disp <= 0x1000 )
                {
                    UINT64 N = Va + Instr.length;
                    for ( int Step = 0; Step < 5 && N < Fn + ScanLimit; ++Step )
                    {
                        ZydisDecodedInstruction Nx;
                        ZydisDecodedOperand     NOps[ZYDIS_MAX_OPERAND_COUNT];
                        if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, reinterpret_cast< void* >( N ),
                            Fn + ScanLimit - N, &Nx, NOps ) ) )
                            break;

                        bool IsAndTest = ( Nx.mnemonic == ZYDIS_MNEMONIC_AND ||
                                           Nx.mnemonic == ZYDIS_MNEMONIC_TEST ) &&
                                         NOps[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                         ( NOps[0].reg.value == ZYDIS_REGISTER_EAX ||
                                           NOps[0].reg.value == ZYDIS_REGISTER_AL );

                        if ( IsAndTest )
                        {
                            EprocessProtectionOffset = static_cast< UINT32 >( Disp );
                            Log( "Offsets: EprocessProtectionOffset -> {}", Disp );
                            return STATUS_SUCCESS;
                        }

                        N += Nx.length;
                    }
                }
            }

            Va += Instr.length;
        }

        LogWarn( "Offsets: EprocessProtectionOffset not found" );
        return STATUS_NOT_FOUND;
    }

    // Find _OBJECT_TYPE.CallbackList offset by scanning ObRegisterCallbacks.
    // Fallback: 0x158 (stable Win10 1903 – Win11 24H2).
    //
    static void ResolveObjTypeCallbackListOffset( ZydisDecoder* Decoder )
    {
        UINT64 Fn = GetRoutine( L"ObRegisterCallbacks" );
        if ( !Fn )
        {
            ObjTypeCallbackListOffset = 0x158;
            Log( "Offsets: ObjTypeCallbackListOffset -> 0x158 (fallback, ObRegisterCallbacks not found)" );
            return;
        }

        constexpr UINT64 ScanLimit = 512;

        for ( UINT64 Va = Fn; Va < Fn + ScanLimit; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, reinterpret_cast< void* >( Va ),
                Fn + ScanLimit - Va, &Instr, Ops ) ) )
            {
                Va++; continue;
            }

            // LEA reg64, [reg64 + disp] in [0x100, 0x280]
            if ( Instr.mnemonic == ZYDIS_MNEMONIC_LEA &&
                 Ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                 Ops[0].size == 64 &&
                 Ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 Ops[1].mem.disp.has_displacement &&
                 Ops[1].mem.base != ZYDIS_REGISTER_RIP &&
                 Ops[1].mem.base != ZYDIS_REGISTER_RSP &&
                 Ops[1].mem.base != ZYDIS_REGISTER_RBP &&
                 Ops[1].mem.index == ZYDIS_REGISTER_NONE )
            {
                INT64 Disp = Ops[1].mem.disp.value;
                if ( Disp >= 0x100 && Disp <= 0x280 )
                {
                    ObjTypeCallbackListOffset = static_cast< UINT32 >( Disp );
                    Log( "Offsets: ObjTypeCallbackListOffset -> {}", Disp );
                    return;
                }
            }

            Va += Instr.length;
        }

        ObjTypeCallbackListOffset = 0x158;
        Log( "Offsets: ObjTypeCallbackListOffset -> 0x158 (fallback)" );
    }

    NTSTATUS Init( )
    {
        Util::DriverInfo NtInfo{};
        if ( !Util::QueryDriver( "ntoskrnl.exe", &NtInfo ) )
        {
            LogWarn( "Offsets: ntoskrnl not found, skipping pattern scan" );
            return STATUS_SUCCESS;
        }

        UINT64 TextStart = 0, TextSize = 0;
        if ( !FindNamedSection( NtInfo.Base, ".text", &TextStart, &TextSize ) )
        {
            LogWarn( "Offsets: .text section not found, skipping pattern scan" );
            return STATUS_SUCCESS;
        }
        UINT64 TextEnd = TextStart + TextSize;

        // PAGE section is required for most PatchGuard and ExAllocateTimer call sites.
        UINT64 PageStart = 0, PageSize = 0;
        FindNamedSection( NtInfo.Base, "PAGE", &PageStart, &PageSize );
        UINT64 PageEnd = PageStart ? PageStart + PageSize : 0;

        ZydisDecoder Decoder;
        ZydisDecoderInit( &Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64 );

        NTSTATUS Status = ResolveKiFilterFiberContext( &Decoder, TextStart, TextEnd, PageStart, PageEnd );
        if ( !NT_SUCCESS( Status ) )
            LogWarn( "Offsets: KiFilterFiberContext not resolved ({})", Status );
        else
        {
            Status = ExtractGlobalsFromKiFilterFiberContext( &Decoder );
            if ( !NT_SUCCESS( Status ) )
                LogWarn( "Offsets: PG globals not extracted ({})", Status );
        }

        Status = ResolveTimerContextOffset( &Decoder, TextStart, TextEnd, PageStart, PageEnd );
        if ( !NT_SUCCESS( Status ) )
            LogWarn( "Offsets: timer context offset not resolved ({})", Status );

        CrossCheckMaxDataSize( &Decoder, TextStart, TextEnd );

        Status = ResolveSmbiosGlobals( &Decoder, TextStart, TextEnd, PageStart, PageEnd );
        if ( !NT_SUCCESS( Status ) )
            LogWarn( "Offsets: SMBIOS globals not resolved ({})", Status );

        Status = ResolveMmUnloadedDrivers( &Decoder, TextStart, TextEnd );
        if ( !NT_SUCCESS( Status ) )
        {
            if ( PageStart )
                Status = ResolveMmUnloadedDrivers( &Decoder, PageStart, PageEnd );
            if ( !NT_SUCCESS( Status ) )
                LogWarn( "Offsets: MmUnloadedDrivers not resolved ({})", Status );
        }

        Status = ResolvePiDDB( &Decoder, TextStart, TextEnd );
        if ( !NT_SUCCESS( Status ) )
        {
            if ( PageStart )
                Status = ResolvePiDDB( &Decoder, PageStart, PageEnd );
            if ( !NT_SUCCESS( Status ) )
                LogWarn( "Offsets: PiDDB not resolved ({})", Status );
        }

        Status = ResolveEprocessProtectionOffset( &Decoder );
        if ( !NT_SUCCESS( Status ) )
            LogWarn( "Offsets: EprocessProtectionOffset not resolved ({})", Status );

        ResolveObjTypeCallbackListOffset( &Decoder );

        // NDIS offsets — scan ndis.sys independently.
        //
        Util::DriverInfo NdisInfo{};
        if ( Util::QueryDriver( "ndis.sys", &NdisInfo ) )
        {
            UINT64 NdisTextStart = 0, NdisTextSize = 0;
            if ( FindNamedSection( NdisInfo.Base, ".text", &NdisTextStart, &NdisTextSize ) )
            {
                UINT64 NdisTextEnd = NdisTextStart + NdisTextSize;

                Status = ResolveNdisMiniportList( &Decoder, NdisTextStart, NdisTextEnd );
                if ( !NT_SUCCESS( Status ) )
                    LogWarn( "Offsets: NdisMiniportList not resolved ({})", Status );

                Status = ResolveNdisStructOffsets( &Decoder, NdisTextStart, NdisTextEnd );
                if ( !NT_SUCCESS( Status ) )
                    LogWarn( "Offsets: NDIS struct offsets not resolved ({})", Status );
            }
            else
            {
                LogWarn( "Offsets: ndis.sys .text not found" );
            }
        }
        else
        {
            LogWarn( "Offsets: ndis.sys not found" );
        }

        return STATUS_SUCCESS;
    }

}
