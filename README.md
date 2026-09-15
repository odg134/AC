# AC

Kernel-mode anti-cheat (WIP)

### Integrations:
- Launcher
- Driver
- Module
- - Manual-mapped module by the Launcher relaying telemetry data from driver to the backend.
- Backend
- - Hono has been used as the framework and Drizzle as ORM (Runs on Bun for best performance).

### Features:
- PE Integrity Checks
- Unloaded driver detections
- - The backend data is synchronized in realtime to MS's XML blocklist and loldrivers.io
- - All data sources from an unloaded driver's packet are tested (such as timestamp or name if the blocklist's entry doesn't contain timestamp)

- Memory region scanning
- - **PTE Walking** (Detect nX bit spoofing)
- - Locate unbacked memory (or RWX PTE's for further scanning)
- - Example:
```cpp
 static void CheckPage( ULONG64 Va, const Pte::HardwarePte& Pte,
                        const Modules::Snapshot& Modules, FindingBuffer& Buf )
 {
     if ( Pte::IsRwx( Pte ) )
         AddFinding( Buf, FindingKind::Rwx, Va, Pte.Value );

     if ( Pte::IsExecutable( Pte ) && !Modules::IsInAny( Modules, Va ) )
         AddFinding( Buf, FindingKind::UnbackedExecutable, Va, Pte.Value );
 }
 ```
- VM detection
- - A lot of tricks have been implemented for **Hyper-V** detection (to ensure it's not **being spoofed**)
- - Undocumented hypercalls are being sent and their result queried aswell as other implementations.
- PatchGuard/KPP integrity checking
- - Checks PG's routines have successfully been executed (to avoid certain types of complete **boot**-time bypasses)
- HWID Queries
- - Queries Disk (**including S.M.A.R.T data**)
- - - Takes in multiple disks requests and sends back any mismatch as a detection in telemetry (in-case a **HWID spoofer** were to have missed a place to spoof)
- - Queries SMBIOS Tables
- - - **Baseboard**
- - - **BIOS**
- - - **Chassis**
- - - **Memory** (Type 17/Memory Devices structures)
- - - **Processor** (For data collection on telemetry, no unique serials)
- - - **System**
- Automated offset resolving for some undocumented routines **using Zydis**
- - Tested on all windows versions from Win10 21h1 to Win11 26h1
- Game process protection
- - Handle guarding through **ObRegisterCallbacks**
- - **PPL process protection** (avoid unauthorized access originating from **csrss, lsass, etc..**)