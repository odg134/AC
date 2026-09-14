#include <Misc/Incl.h>
#include <Core/Offsets/Offsets.h>
#include <Core/Environment/PG/PG.h>

/// <summary>
/// Verify PatchGuard/KPP's integrity and that it has not been tampered with.
/// </summary>
/// <returns></returns>
NTSTATUS PG::VerifyPresence( )
{
    if ( !Offsets::MaxDataSize || !Offsets::PsIntegrityCheckEnabled || !Offsets::CallbackHealthFlag )
        return STATUS_NOT_FOUND;

    UINT64 Ctx = *Offsets::MaxDataSize;
    if ( !Ctx )
        return STATUS_UNSUCCESSFUL;

    if ( !*Offsets::PsIntegrityCheckEnabled || !*Offsets::CallbackHealthFlag )
        return STATUS_UNSUCCESSFUL;

    PVOID Tmr = *( PVOID* )( Ctx + Offsets::Timer );
    if ( !MmIsAddressValid( Tmr ) )
        return STATUS_UNSUCCESSFUL;

    // EX_TIMER_HIGH_RESOLUTION
    //
    if ( *( ULONG* )( ( PUCHAR )Tmr + 0x28 ) != 8 )
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}

/// <summary>
/// </summary>
/// <returns></returns>
NTSTATUS PG::Initialize( )
{
    return STATUS_SUCCESS;
}
