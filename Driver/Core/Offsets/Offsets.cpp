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

    // Locate WmipSMBiosTablePhysicalAddress and WmipSMBiosTableLength by scanning
    // for the unique sequence in WmipGetSMBiosTableData:
    //   TEST RCX, RCX  /  JZ  /  MOV EDX, EAX  /  MOV R8D, 4
    // then walking backwards to the two RIP-relative MOVs that precede it.
    //
    static NTSTATUS ResolveSmbiosGlobals( ZydisDecoder* Decoder, UINT64 TextStart, UINT64 TextEnd )
    {
        for ( UINT64 Va = TextStart; Va < TextEnd; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )Va, TextEnd - Va, &Instr, Ops ) ) )
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

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )N, TextEnd - N, &I2, O2 ) ) ||
                 I2.mnemonic != ZYDIS_MNEMONIC_JZ )
            { Va += Instr.length; continue; }

            N += I2.length;

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )N, TextEnd - N, &I3, O3 ) ) ||
                 I3.mnemonic != ZYDIS_MNEMONIC_MOV ||
                 O3[0].type != ZYDIS_OPERAND_TYPE_REGISTER || O3[0].reg.value != ZYDIS_REGISTER_EDX ||
                 O3[1].type != ZYDIS_OPERAND_TYPE_REGISTER || O3[1].reg.value != ZYDIS_REGISTER_EAX )
            { Va += Instr.length; continue; }

            N += I3.length;

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, ( void* )N, TextEnd - N, &I4, O4 ) ) ||
                 I4.mnemonic != ZYDIS_MNEMONIC_MOV ||
                 O4[0].type != ZYDIS_OPERAND_TYPE_REGISTER || O4[0].reg.value != ZYDIS_REGISTER_R8D ||
                 O4[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || O4[1].imm.value.u != 4 )
            { Va += Instr.length; continue; }

            // Found the anchor. Walk a lookback window to find the two RIP-relative
            // MOVs that feed EAX (TableLength) and RCX (TablePhysicalAddress).
            //
            UINT64 Window = ( Va > TextStart + 80 ) ? Va - 80 : TextStart;

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

            return STATUS_SUCCESS;
        }

        LogError( "Offsets: SMBIOS globals not found" );
        return STATUS_NOT_FOUND;
    }

    // Locate ndisMiniportList by finding the distinctive three-instruction sequence in
    // ndisRemoveMiniportFromGlobalList that appears immediately after the
    // KeAcquireSpinLockRaiseToDpc call:
    //
    //   MOVZX r8d, al               ; save old IRQL in r8b
    //   LEA   r9,  [RIP + rel32]    ; <-- address of ndisMiniportList
    //   MOV   rdx, [r9]             ; dereference to head of list
    //   TEST  rdx, rdx              ; check whether list is empty
    //
    static NTSTATUS ResolveNdisMiniportList(
        ZydisDecoder* Decoder, UINT64 TextStart, UINT64 TextEnd )
    {
        for ( UINT64 Va = TextStart; Va < TextEnd; )
        {
            ZydisDecodedInstruction I1;
            ZydisDecodedOperand O1[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)Va, TextEnd - Va, &I1, O1 ) ) )
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

            // LEA r9, [RIP + rel32]
            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)N, TextEnd - N, &I2, O2 ) ) ||
                 I2.mnemonic != ZYDIS_MNEMONIC_LEA ||
                 O2[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                 O2[0].reg.value != ZYDIS_REGISTER_R9 ||
                 O2[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                 O2[1].mem.base != ZYDIS_REGISTER_RIP )
            {
                Va += I1.length; continue;
            }

            N += I2.length;

            // MOV rdx, [r9]
            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)N, TextEnd - N, &I3, O3 ) ) ||
                 I3.mnemonic != ZYDIS_MNEMONIC_MOV ||
                 O3[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                 O3[0].reg.value != ZYDIS_REGISTER_RDX ||
                 O3[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                 O3[1].mem.base != ZYDIS_REGISTER_R9 )
            {
                Va += I1.length; continue;
            }

            N += I3.length;

            // TEST rdx, rdx
            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)N, TextEnd - N, &I4, O4 ) ) ||
                 I4.mnemonic != ZYDIS_MNEMONIC_TEST ||
                 O4[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                 O4[0].reg.value != ZYDIS_REGISTER_RDX ||
                 O4[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                 O4[1].reg.value != ZYDIS_REGISTER_RDX )
            {
                Va += I1.length; continue;
            }

            ZydisCalcAbsoluteAddress( &I2, &O2[1], Va + I1.length, &NdisMiniportList );
            Log( "Offsets: NdisMiniportList -> {}", NdisMiniportList );
            return STATUS_SUCCESS;
        }

        LogError( "Offsets: NdisMiniportList pattern not found" );
        return STATUS_NOT_FOUND;
    }

    // Resolve NDIS_MINIPORT_BLOCK::NextGlobalMiniport offset by finding the
    // self-referential loop: MOV reg, [same_reg + disp] / TEST reg, reg / JNZ-back
    // that walks the global miniport list.
    //
    // Also resolves NDIS_IF_BLOCK field offsets from ndisIfUpdateCurrentMacAddress,
    // identified by the distinctive prologue pattern:
    //
    //   MOVZX esi, word ptr [rdi]   ; read incoming MAC length from IF_PHYS_ADDR
    //   MOVZX ebp, al               ; save IRQL
    //   CMP   [rbx + disp], si      ; compare with stored current MAC length
    //
    static NTSTATUS ResolveNdisStructOffsets(
        ZydisDecoder* Decoder, UINT64 TextStart, UINT64 TextEnd )
    {
        // Find the self-referential MOV to extract NdisMpNextOffset.
        //
        bool FoundNext = false;
        for ( UINT64 Va = TextStart; Va < TextEnd && !FoundNext; )
        {
            ZydisDecodedInstruction I1;
            ZydisDecodedOperand O1[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)Va, TextEnd - Va, &I1, O1 ) ) )
            {
                Va++; continue;
            }

            // MOV reg64, [same_reg64 + disp32]  in the range 0xE00-0x1100
            if ( I1.mnemonic == ZYDIS_MNEMONIC_MOV &&
                 O1[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                 O1[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 O1[1].mem.base == O1[0].reg.value &&
                 O1[1].mem.disp.has_displacement &&
                 O1[1].mem.disp.value >= 0xE00 &&
                 O1[1].mem.disp.value <= 0x1100 &&
                 O1[0].size == 64 )
            {
                UINT64 N = Va + I1.length;
                auto   Reg = O1[0].reg.value;
                UINT64 Disp = (UINT64)O1[1].mem.disp.value;

                ZydisDecodedInstruction I2, I3;
                ZydisDecodedOperand     O2[ZYDIS_MAX_OPERAND_COUNT],
                                        O3[ZYDIS_MAX_OPERAND_COUNT];

                // TEST same_reg, same_reg
                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)N, TextEnd - N, &I2, O2 ) ) ||
                     I2.mnemonic != ZYDIS_MNEMONIC_TEST ||
                     O2[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                     O2[0].reg.value != Reg ||
                     O2[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                     O2[1].reg.value != Reg )
                {
                    Va += I1.length; continue;
                }

                N += I2.length;

                // JNZ (backward branch back into the loop)
                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)N, TextEnd - N, &I3, O3 ) ) ||
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
        // Then extract: CMP [rbx+disp], si -> disp = NdisIfCurrentMacLen
        //               LEA rcx, [rbx+disp+2]   -> NdisIfCurrentMac
        //
        // We also expect a second CMP/LEA pair for the permanent MAC further down.
        //
        bool FoundCurrentMac   = false;
        bool FoundPermanentMac = false;

        for ( UINT64 Va = TextStart; Va < TextEnd && !( FoundCurrentMac && FoundPermanentMac ); )
        {
            ZydisDecodedInstruction I1;
            ZydisDecodedOperand O1[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)Va, TextEnd - Va, &I1, O1 ) ) )
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
            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)N, TextEnd - N, &I2, O2 ) ) ||
                 I2.mnemonic != ZYDIS_MNEMONIC_MOVZX ||
                 O2[0].type  != ZYDIS_OPERAND_TYPE_REGISTER ||
                 O2[0].reg.value != ZYDIS_REGISTER_EBP ||
                 O2[1].type  != ZYDIS_OPERAND_TYPE_REGISTER ||
                 O2[1].reg.value != ZYDIS_REGISTER_AL )
            {
                Va += I1.length; continue;
            }

            // Scan forward up to 12 bytes to find CMP [rbx+disp], si
            //
            UINT64 Limit = N + I2.length + 12;
            if ( Limit > TextEnd ) Limit = TextEnd;
            UINT64 Scan = N + I2.length;

            while ( Scan < Limit )
            {
                ZydisDecodedInstruction Ix;
                ZydisDecodedOperand Ox[ZYDIS_MAX_OPERAND_COUNT];

                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)Scan, Limit - Scan, &Ix, Ox ) ) )
                    break;

                if ( Ix.mnemonic == ZYDIS_MNEMONIC_CMP &&
                     Ox[0].type  == ZYDIS_OPERAND_TYPE_MEMORY &&
                     Ox[0].mem.base == ZYDIS_REGISTER_RBX &&
                     Ox[0].mem.disp.has_displacement &&
                     Ox[0].mem.disp.value > 0x400 &&
                     Ox[0].mem.disp.value < 0x520 &&
                     Ox[1].type  == ZYDIS_OPERAND_TYPE_REGISTER &&
                     Ox[1].reg.value == ZYDIS_REGISTER_SI )
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
                    else if ( !FoundPermanentMac )
                    {
                        NdisIfPermMacLen = static_cast< UINT32 >( Disp );
                        NdisIfPermMac    = static_cast< UINT32 >( Disp + 2 );
                        Log( "Offsets: NdisIfPermMacLen -> {}", Disp );
                        Log( "Offsets: NdisIfPermMac -> {}", Disp + 2 );
                        FoundPermanentMac = true;
                    }

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

        // Derive NdisMpIfBlockOffset from the relationship: just before accessing
        // the current MAC offset we saw, a MOV loads the IF_BLOCK pointer from the
        // miniport block.  Find that: MOV reg64, [rcx + disp32] immediately followed
        // (within 10 bytes) by an access to [reg64 + NdisIfCurrentMacLen].
        //
        for ( UINT64 Va = TextStart; Va < TextEnd; )
        {
            ZydisDecodedInstruction I1;
            ZydisDecodedOperand O1[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)Va, TextEnd - Va, &I1, O1 ) ) )
            {
                Va++; continue;
            }

            if ( I1.mnemonic == ZYDIS_MNEMONIC_MOV &&
                 O1[0].type  == ZYDIS_OPERAND_TYPE_REGISTER &&
                 O1[0].size  == 64 &&
                 O1[1].type  == ZYDIS_OPERAND_TYPE_MEMORY &&
                 O1[1].mem.base == ZYDIS_REGISTER_RCX &&
                 O1[1].mem.disp.has_displacement &&
                 O1[1].mem.disp.value > 0xE00 &&
                 O1[1].mem.disp.value < 0x1100 )
            {
                auto   IfReg = O1[0].reg.value;
                UINT64 Disp  = (UINT64)O1[1].mem.disp.value;
                UINT64 N     = Va + I1.length;
                UINT64 Limit = N + 10;
                if ( Limit > TextEnd ) Limit = TextEnd;

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
                    // Verify followed by AND/TEST on AL or EAX within 5 instructions.
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
    // Pattern: LEA R??, [R?? + disp] where disp in [0x100, 0x280] applied to a
    // pointer that was loaded from an ObjectType argument.
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

    // Locate MmUnloadedDrivers (PVOID* to the circular array) and MmLastUnloadedDriver
    // (ULONG* write index) by anchoring on MOV r8d, 54446D4Dh ('MMdT' pool tag) inside
    // MiTrackUnloadedDrivers.  The array pointer load (TEST reg,reg pattern) precedes the
    // anchor; the index load (CMP reg32, 32h) follows it.
    //
    static NTSTATUS ResolveMmUnloadedDrivers( ZydisDecoder* Decoder, UINT64 TextStart, UINT64 TextEnd )
    {
        for ( UINT64 Va = TextStart; Va < TextEnd; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand     Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)Va, TextEnd - Va, &Instr, Ops ) ) )
            { Va++; continue; }

            // Anchor: MOV r8d, 54446D4Dh
            if ( !( Instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    Ops[0].type    == ZYDIS_OPERAND_TYPE_REGISTER &&
                    Ops[0].reg.value == ZYDIS_REGISTER_R8D &&
                    Ops[1].type    == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    Ops[1].imm.value.u == 0x54446D4DUL ) )
            { Va += Instr.length; continue; }

            // --- backward window: find MOV reg64, [RIP+rel] followed by TEST reg64, reg64 ---
            UINT64 WinStart = ( Va > TextStart + 0x100 ) ? Va - 0x100 : TextStart;

            // Collect instruction addresses in the window (forward pass).
            UINT64 InsVa[64]{};
            UCHAR  InsLen[64]{};
            ULONG  InsCount = 0;

            for ( UINT64 V2 = WinStart; V2 < Va && InsCount < 64; )
            {
                ZydisDecodedInstruction Ix;
                ZydisDecodedOperand     Ox[ZYDIS_MAX_OPERAND_COUNT];
                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)V2, Va - V2, &Ix, Ox ) ) )
                { V2++; continue; }
                InsVa[InsCount]  = V2;
                InsLen[InsCount] = static_cast<UCHAR>( Ix.length );
                ++InsCount;
                V2 += Ix.length;
            }

            // Walk collected instructions looking for last MOV reg64,[RIP+rel] + TEST reg64,reg64.
            UINT64 UnloadedArray = 0;
            for ( int K = 0; K + 1 < (int)InsCount && !UnloadedArray; ++K )
            {
                ZydisDecodedInstruction Ia, Ib;
                ZydisDecodedOperand     Oa[ZYDIS_MAX_OPERAND_COUNT],
                                        Ob[ZYDIS_MAX_OPERAND_COUNT];

                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)InsVa[K],   32, &Ia, Oa ) ) ) continue;
                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)InsVa[K+1], 32, &Ib, Ob ) ) ) continue;

                if ( Ia.mnemonic == ZYDIS_MNEMONIC_MOV &&
                     Oa[0].type  == ZYDIS_OPERAND_TYPE_REGISTER &&
                     Oa[0].size  == 64 &&
                     Oa[1].type  == ZYDIS_OPERAND_TYPE_MEMORY &&
                     Oa[1].mem.base == ZYDIS_REGISTER_RIP &&
                     Ib.mnemonic == ZYDIS_MNEMONIC_TEST &&
                     Ob[0].type  == ZYDIS_OPERAND_TYPE_REGISTER &&
                     Ob[0].reg.value == Oa[0].reg.value )
                {
                    // This pair could be the one; keep updating so we pick the last one.
                    ZydisCalcAbsoluteAddress( &Ia, &Oa[1], InsVa[K], &UnloadedArray );
                }
            }

            if ( !UnloadedArray )
            { Va += Instr.length; continue; }

            // --- forward window: find MOV reg32,[RIP+rel] + CMP reg32, 32h ---
            UINT64 FwdEnd = min( Va + 0x80, TextEnd );
            UINT64 LastIdx = 0;

            for ( UINT64 V2 = Va + Instr.length; V2 < FwdEnd; )
            {
                ZydisDecodedInstruction Ia, Ib;
                ZydisDecodedOperand     Oa[ZYDIS_MAX_OPERAND_COUNT],
                                        Ob[ZYDIS_MAX_OPERAND_COUNT];

                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)V2, FwdEnd - V2, &Ia, Oa ) ) )
                { V2++; continue; }

                UINT64 Nb = V2 + Ia.length;
                if ( Nb >= FwdEnd ) break;

                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)Nb, FwdEnd - Nb, &Ib, Ob ) ) )
                { V2 += Ia.length; continue; }

                if ( Ia.mnemonic == ZYDIS_MNEMONIC_MOV &&
                     Oa[0].type  == ZYDIS_OPERAND_TYPE_REGISTER &&
                     Oa[0].size  == 32 &&
                     Oa[1].type  == ZYDIS_OPERAND_TYPE_MEMORY &&
                     Oa[1].mem.base == ZYDIS_REGISTER_RIP &&
                     Ib.mnemonic == ZYDIS_MNEMONIC_CMP &&
                     Ob[1].type  == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                     Ob[1].imm.value.u == 0x32 )
                {
                    ZydisCalcAbsoluteAddress( &Ia, &Oa[1], V2, &LastIdx );
                    break;
                }

                V2 += Ia.length;
            }

            if ( !LastIdx )
            { Va += Instr.length; continue; }

            MmUnloadedDrivers    = reinterpret_cast<PVOID*>( UnloadedArray );
            MmLastUnloadedDriver = reinterpret_cast<ULONG*>( LastIdx );

            Log( "Offsets: MmUnloadedDrivers -> {}", UnloadedArray );
            Log( "Offsets: MmLastUnloadedDriver -> {}", LastIdx );
            return STATUS_SUCCESS;
        }

        LogError( "Offsets: MmUnloadedDrivers pattern not found" );
        return STATUS_NOT_FOUND;
    }

    // Locate PiDDBCacheTable (RTL_AVL_TABLE*) and PiDDBLock (ERESOURCE*) by finding the
    // call to RtlIsGenericTableEmptyAvl and tracing back to the LEA rcx that loads the
    // table address.  PiDDBLock is the LEA rcx before the closest ExAcquireResource* call
    // that precedes the table check.
    //
    static NTSTATUS ResolvePiDDBCacheTable( ZydisDecoder* Decoder, UINT64 TextStart, UINT64 TextEnd )
    {
        UINT64 AddrRtlEmpty = GetRoutine( L"RtlIsGenericTableEmptyAvl" );
        UINT64 AddrExAcqEx  = GetRoutine( L"ExAcquireResourceExclusiveLite" );
        UINT64 AddrExAcqSh  = GetRoutine( L"ExAcquireResourceSharedLite" );

        if ( !AddrRtlEmpty )
        {
            LogError( "Offsets: RtlIsGenericTableEmptyAvl not found" );
            return STATUS_NOT_FOUND;
        }

        for ( UINT64 Va = TextStart; Va < TextEnd; )
        {
            ZydisDecodedInstruction Instr;
            ZydisDecodedOperand     Ops[ZYDIS_MAX_OPERAND_COUNT];

            if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)Va, TextEnd - Va, &Instr, Ops ) ) )
            { Va++; continue; }

            if ( Instr.mnemonic != ZYDIS_MNEMONIC_CALL )
            { Va += Instr.length; continue; }

            // Support both direct (E8) and indirect (FF 15) calls.
            UINT64 CallTarget = 0;
            if ( Ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE )
                ZydisCalcAbsoluteAddress( &Instr, &Ops[0], Va, &CallTarget );
            else if ( Ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                      Ops[0].mem.base == ZYDIS_REGISTER_RIP )
            {
                UINT64 Slot = 0;
                ZydisCalcAbsoluteAddress( &Instr, &Ops[0], Va, &Slot );
                CallTarget = *reinterpret_cast<UINT64*>( Slot );
            }

            if ( CallTarget != AddrRtlEmpty )
            { Va += Instr.length; continue; }

            // Found the call.  Collect the backward window.
            UINT64 WinStart = ( Va > TextStart + 0x100 ) ? Va - 0x100 : TextStart;

            UINT64 InsVa[64]{};
            UCHAR  InsLen[64]{};
            ULONG  InsCount = 0;

            for ( UINT64 V2 = WinStart; V2 < Va && InsCount < 64; )
            {
                ZydisDecodedInstruction Ix;
                ZydisDecodedOperand     Ox[ZYDIS_MAX_OPERAND_COUNT];
                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)V2, Va - V2, &Ix, Ox ) ) )
                { V2++; continue; }
                InsVa[InsCount]  = V2;
                InsLen[InsCount] = static_cast<UCHAR>( Ix.length );
                ++InsCount;
                V2 += Ix.length;
            }

            // PiDDBCacheTable: the last LEA rcx,[RIP+rel] before the RtlIsGenericTableEmptyAvl call.
            UINT64 TableAddr = 0;
            for ( int K = (int)InsCount - 1; K >= 0 && !TableAddr; --K )
            {
                ZydisDecodedInstruction Ix;
                ZydisDecodedOperand     Ox[ZYDIS_MAX_OPERAND_COUNT];
                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)InsVa[K], 16, &Ix, Ox ) ) ) continue;

                if ( Ix.mnemonic == ZYDIS_MNEMONIC_LEA &&
                     Ox[0].type  == ZYDIS_OPERAND_TYPE_REGISTER &&
                     Ox[0].reg.value == ZYDIS_REGISTER_RCX &&
                     Ox[1].type  == ZYDIS_OPERAND_TYPE_MEMORY &&
                     Ox[1].mem.base == ZYDIS_REGISTER_RIP )
                {
                    ZydisCalcAbsoluteAddress( &Ix, &Ox[1], InsVa[K], &TableAddr );
                }
            }

            if ( !TableAddr )
            { Va += Instr.length; continue; }

            // PiDDBLock: LEA rcx,[RIP+rel] directly before a CALL ExAcquireResource*.
            UINT64 LockAddr = 0;
            for ( ULONG K = 0; K + 1 < InsCount && !LockAddr; ++K )
            {
                ZydisDecodedInstruction Ia, Ib;
                ZydisDecodedOperand     Oa[ZYDIS_MAX_OPERAND_COUNT],
                                        Ob[ZYDIS_MAX_OPERAND_COUNT];

                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)InsVa[K],   16, &Ia, Oa ) ) ) continue;
                if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( Decoder, (void*)InsVa[K+1], 16, &Ib, Ob ) ) ) continue;

                if ( !( Ia.mnemonic == ZYDIS_MNEMONIC_LEA &&
                        Oa[0].type  == ZYDIS_OPERAND_TYPE_REGISTER &&
                        Oa[0].reg.value == ZYDIS_REGISTER_RCX &&
                        Oa[1].type  == ZYDIS_OPERAND_TYPE_MEMORY &&
                        Oa[1].mem.base == ZYDIS_REGISTER_RIP ) )
                    continue;

                if ( Ib.mnemonic != ZYDIS_MNEMONIC_CALL )
                    continue;

                UINT64 AcqTarget = 0;
                if ( Ob[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE )
                    ZydisCalcAbsoluteAddress( &Ib, &Ob[0], InsVa[K+1], &AcqTarget );
                else if ( Ob[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                          Ob[0].mem.base == ZYDIS_REGISTER_RIP )
                {
                    UINT64 Slot = 0;
                    ZydisCalcAbsoluteAddress( &Ib, &Ob[0], InsVa[K+1], &Slot );
                    AcqTarget = *reinterpret_cast<UINT64*>( Slot );
                }

                if ( ( AddrExAcqEx && AcqTarget == AddrExAcqEx ) ||
                     ( AddrExAcqSh && AcqTarget == AddrExAcqSh ) )
                {
                    ZydisCalcAbsoluteAddress( &Ia, &Oa[1], InsVa[K], &LockAddr );
                }
            }

            PiDDBCacheTable = reinterpret_cast<PVOID>( TableAddr );
            Log( "Offsets: PiDDBCacheTable -> {}", TableAddr );

            if ( LockAddr )
            {
                PiDDBLock = reinterpret_cast<PVOID>( LockAddr );
                Log( "Offsets: PiDDBLock -> {}", LockAddr );
            }
            else
                LogWarn( "Offsets: PiDDBLock not found near PiDDBCacheTable" );

            return STATUS_SUCCESS;
        }

        LogError( "Offsets: PiDDBCacheTable not found" );
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
            LogWarn( "Offsets: ntoskrnl not found, skipping pattern scan" );
            return STATUS_SUCCESS;
        }

        UINT64 TextStart = 0, TextSize = 0;
        if ( !FindTextSection( NtInfo.Base, &TextStart, &TextSize ) )
        {
            LogWarn( "Offsets: .text section not found, skipping pattern scan" );
            return STATUS_SUCCESS;
        }

        UINT64 TextEnd = TextStart + TextSize;

        ZydisDecoder Decoder;
        ZydisDecoderInit( &Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64 );

        NTSTATUS Status = ResolveKiFilterFiberContext( &Decoder, TextStart, TextEnd );
        if ( !NT_SUCCESS( Status ) )
            LogWarn( "Offsets: KiFilterFiberContext not resolved ({})", Status );
        else
        {
            Status = ExtractGlobalsFromKiFilterFiberContext( &Decoder );
            if ( !NT_SUCCESS( Status ) )
                LogWarn( "Offsets: PG globals not extracted ({})", Status );
        }

        Status = ResolveTimerContextOffset( &Decoder, TextStart, TextEnd );
        if ( !NT_SUCCESS( Status ) )
            LogWarn( "Offsets: timer context offset not resolved ({})", Status );

        CrossCheckMaxDataSize( &Decoder, TextStart, TextEnd );

        Status = ResolveSmbiosGlobals( &Decoder, TextStart, TextEnd );
        if ( !NT_SUCCESS( Status ) )
            LogWarn( "Offsets: SMBIOS globals not resolved ({})", Status );

        // Process protection + ObCallback integrity offsets.
        //
        Status = ResolveEprocessProtectionOffset( &Decoder );
        if ( !NT_SUCCESS( Status ) )
            LogWarn( "Offsets: EprocessProtectionOffset not resolved ({})", Status );

        ResolveObjTypeCallbackListOffset( &Decoder );

        // NDIS offsets | scan ndis.sys independently.
        //
        Util::DriverInfo NdisInfo{};
        if ( Util::QueryDriver( "ndis.sys", &NdisInfo ) )
        {
            UINT64 NdisTextStart = 0, NdisTextSize = 0;
            if ( FindTextSection( NdisInfo.Base, &NdisTextStart, &NdisTextSize ) )
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
