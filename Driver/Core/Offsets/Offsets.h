#pragma once
#include <ntddk.h>

namespace Offsets
{
    inline UINT64  KiFilterFiberContext{};
    inline UINT64* MaxDataSize{};
    inline UINT32* CallbackHealthFlag{};
    inline UINT32* PsIntegrityCheckEnabled{};
    inline UINT64  KiInitData{};
    inline UINT64  Timer{};

    // ntoskrnl SMBIOS globals resolved via the WmipGetSMBiosTableData scan.
    // Null until Init() succeeds.
    //
    inline UINT64* WmipSMBiosTablePhysicalAddress{};
    inline UINT32* WmipSMBiosTableLength{};

    // ndis.sys NDIS internals resolved via pattern scanning.
    //
    // Runtime address of the ndisMiniportList global (NDIS_MINIPORT_BLOCK*).
    inline UINT64 NdisMiniportList{};

    // Field offsets within NDIS_MINIPORT_BLOCK.
    inline UINT32 NdisMpNextOffset{};     // pointer to next block in the global list
    inline UINT32 NdisMpIfBlockOffset{};  // pointer to the associated NDIS_IF_BLOCK

    // Field offsets within NDIS_IF_BLOCK.
    inline UINT32 NdisIfCurrentMacLen{};  // USHORT: current (possibly spoofed) MAC length
    inline UINT32 NdisIfCurrentMac{};     // UCHAR[32]: current MAC address bytes
    inline UINT32 NdisIfPermMacLen{};     // USHORT: permanent (burned-in) MAC length
    inline UINT32 NdisIfPermMac{};        // UCHAR[32]: permanent MAC address bytes

    NTSTATUS Init( );
}
