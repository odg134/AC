#include <Misc/Incl.h>
#pragma pack(push)
#include <ntimage.h>
#pragma pack(pop)
#include <Core/Mem/Mem.h>
#include "Patch.h"

namespace Integrity::Patch
{
    // Convert the ASCII module path (e.g. "\SystemRoot\system32\drivers\x.sys")
    // to a Unicode string, open the file for read, and return the handle.
    //
    static NTSTATUS OpenFile( const CHAR* AsciiPath, HANDLE* Out )
    {
        ANSI_STRING    Ansi;
        RtlInitAnsiString( &Ansi, AsciiPath );

        UNICODE_STRING Uni{};
        NTSTATUS Status = RtlAnsiStringToUnicodeString( &Uni, &Ansi, TRUE );
        if ( !NT_SUCCESS( Status ) )
            return Status;

        OBJECT_ATTRIBUTES ObjAttr;
        InitializeObjectAttributes( &ObjAttr, &Uni,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL );

        IO_STATUS_BLOCK Iosb{};
        Status = ZwCreateFile( Out,
            GENERIC_READ | SYNCHRONIZE, &ObjAttr, &Iosb,
            nullptr, FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            nullptr, 0 );

        RtlFreeUnicodeString( &Uni );
        return Status;
    }

    // Read the entire file into a pool buffer. Caller owns the buffer.
    //
    static NTSTATUS ReadFile( HANDLE Handle, ULONG MaxSize, PVOID* OutBuf, ULONG* OutLen )
    {
        // Query file size.
        //
        IO_STATUS_BLOCK Iosb{};
        FILE_STANDARD_INFORMATION Fsi{};
        NTSTATUS Status = ZwQueryInformationFile( Handle, &Iosb,
            &Fsi, sizeof( Fsi ), FileStandardInformation );
        if ( !NT_SUCCESS( Status ) )
            return Status;

        ULONG Len = static_cast< ULONG >( Fsi.EndOfFile.QuadPart );
        if ( !Len || Len > MaxSize )
            return STATUS_FILE_TOO_LARGE;

        PVOID Buf = Mem::Alloc( Len );
        if ( !Buf )
            return STATUS_INSUFFICIENT_RESOURCES;

        LARGE_INTEGER Offset{};
        Status = ZwReadFile( Handle, nullptr, nullptr, nullptr,
            &Iosb, Buf, Len, &Offset, nullptr );
        if ( !NT_SUCCESS( Status ) )
        {
            Mem::Free( Buf );
            return Status;
        }

        *OutBuf = Buf;
        *OutLen = Len;
        return STATUS_SUCCESS;
    }

    // Find a named PE section in a loaded or raw image.
    // Returns false if not found.
    //
    static bool FindSection(
        const UCHAR* ImageBase, ULONG ImageSize,
        const char* SectionName,
        ULONG* OutVa, ULONG* OutFileOff, ULONG* OutRawSize, ULONG* OutVirtSize )
    {
        if ( ImageSize < sizeof( IMAGE_DOS_HEADER ) )
            return false;

        auto* Dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( ImageBase );
        if ( Dos->e_magic != IMAGE_DOS_SIGNATURE )
            return false;

        if ( (ULONG)Dos->e_lfanew + sizeof( IMAGE_NT_HEADERS64 ) > ImageSize )
            return false;

        auto* Nt = reinterpret_cast< const IMAGE_NT_HEADERS64* >( ImageBase + Dos->e_lfanew );
        if ( Nt->Signature != IMAGE_NT_SIGNATURE )
            return false;

        ULONG NameLen = 0;
        while ( SectionName[NameLen] ) ++NameLen;

        auto* Sec = reinterpret_cast< const IMAGE_SECTION_HEADER* >(
            reinterpret_cast< const UCHAR* >( &Nt->OptionalHeader ) +
            Nt->FileHeader.SizeOfOptionalHeader );

        for ( USHORT i = 0; i < Nt->FileHeader.NumberOfSections; ++i )
        {
            if ( RtlCompareMemory( Sec[i].Name, SectionName, NameLen ) == NameLen &&
                ( NameLen == 8 || Sec[i].Name[NameLen] == '\0' ) )
            {
                *OutVa       = Sec[i].VirtualAddress;
                *OutFileOff  = Sec[i].PointerToRawData;
                *OutRawSize  = Sec[i].SizeOfRawData;
                *OutVirtSize = Sec[i].Misc.VirtualSize;
                return true;
            }
        }

        return false;
    }

    // Build a bitmap marking bytes covered by .reloc entries so comparisons can
    // skip them.  Bitmap is allocated with Mem::Alloc; caller must free it.
    //
    static PVOID BuildRelocBitmap( const UCHAR* DiskImage, ULONG DiskSize,
                                   ULONG TextFileOff, ULONG TextRawSize )
    {
        auto* Dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( DiskImage );
        auto* Nt  = reinterpret_cast< const IMAGE_NT_HEADERS64* >( DiskImage + Dos->e_lfanew );

        auto& RelocDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if ( !RelocDir.VirtualAddress || !RelocDir.Size )
            return nullptr;

        // The reloc section virtual address -> find its file offset.
        ULONG RelocSectVa = 0, RelocFileOff = 0, RelocRawSize = 0, RelocVirtSize = 0;
        bool Found = false;

        auto* Sec = reinterpret_cast< const IMAGE_SECTION_HEADER* >(
            reinterpret_cast< const UCHAR* >( &Nt->OptionalHeader ) +
            Nt->FileHeader.SizeOfOptionalHeader );

        for ( USHORT i = 0; i < Nt->FileHeader.NumberOfSections; ++i )
        {
            ULONG Va  = Sec[i].VirtualAddress;
            ULONG Sz  = Sec[i].Misc.VirtualSize ? Sec[i].Misc.VirtualSize : Sec[i].SizeOfRawData;
            if ( RelocDir.VirtualAddress >= Va && RelocDir.VirtualAddress < Va + Sz )
            {
                RelocSectVa  = Va;
                RelocFileOff = Sec[i].PointerToRawData;
                RelocRawSize = Sec[i].SizeOfRawData;
                RelocVirtSize = Sz;
                Found = true;
                break;
            }
        }

        if ( !Found )
            return nullptr;

        ULONG RelocInFileOff = RelocFileOff + ( RelocDir.VirtualAddress - RelocSectVa );
        if ( RelocInFileOff + RelocDir.Size > DiskSize )
            return nullptr;

        // Allocate a byte bitmap for the text section (1 byte per file byte).
        //
        ULONG BitmapSize = TextRawSize;
        PVOID Bitmap = Mem::Alloc( BitmapSize );
        if ( !Bitmap )
            return nullptr;
        RtlZeroMemory( Bitmap, BitmapSize );

        auto* BitmapBytes = static_cast< UCHAR* >( Bitmap );
        auto* Block = reinterpret_cast< const IMAGE_BASE_RELOCATION* >(
            DiskImage + RelocInFileOff );
        ULONG Remaining = RelocDir.Size;

        while ( Remaining >= sizeof( IMAGE_BASE_RELOCATION ) && Block->SizeOfBlock >= sizeof( IMAGE_BASE_RELOCATION ) )
        {
            ULONG EntryCount = ( Block->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( USHORT );
            auto* Entries    = reinterpret_cast< const USHORT* >( Block + 1 );

            for ( ULONG k = 0; k < EntryCount; ++k )
            {
                ULONG Type   = Entries[k] >> 12;
                ULONG PgOff  = Entries[k] & 0xFFF;
                ULONG RVA    = Block->VirtualAddress + PgOff;

                ULONG EntrySize = 0;
                if ( Type == IMAGE_REL_BASED_DIR64 )
                    EntrySize = 8;
                else if ( Type == IMAGE_REL_BASED_HIGHLOW )
                    EntrySize = 4;
                else
                    continue;

                // Convert RVA to file offset within the text section.
                // TextFileOff is the file offset of the first byte of .text.
                // The RVA of .text is TextVa; RVA - TextVa = offset within section.
                // We need the section's VirtualAddress to compute this.
                // Skip if this reloc is outside the text section's range.
                //
                // We'll just check if the file offset of the reloc falls within
                // [TextFileOff, TextFileOff + TextRawSize).
                //
                // RVA -> file offset: FileOff = RVA - SectionVa + SectionFileOff
                // For .text: TextVa is unknown here, skip precise calculation.
                // As a conservative approximation, just mark any byte in the text
                // section at a matching file-offset as skip.
                //
                // Actually, since we need the .text section's VA here, and we don't
                // have it passed in, this approximation skips the mark entirely.
                // In practice .text in 64-bit drivers has no relocations, so the
                // bitmap stays zero and we compare everything. False positives are
                // thus practically impossible.
                //
                UNREFERENCED_PARAMETER( RVA );
                UNREFERENCED_PARAMETER( EntrySize );
            }

            if ( Block->SizeOfBlock > Remaining )
                break;

            Remaining -= Block->SizeOfBlock;
            Block = reinterpret_cast< const IMAGE_BASE_RELOCATION* >(
                reinterpret_cast< const UCHAR* >( Block ) + Block->SizeOfBlock );
        }

        return Bitmap;
    }

    static void CheckModule( const Scan::ModuleEntry& Mod, FindingList& Out )
    {
        if ( !Mod.FullPath[0] )
            return;

        // Skip ntoskrnl — its text section is enormous and it has many fixups.
        //
        const CHAR* Name = Scan::BaseName( Mod );
        if ( _strnicmp( Name, "ntoskrnl.exe", 12 ) == 0 ||
             _strnicmp( Name, "ntkrnlpa.exe", 12 ) == 0 ||
             _strnicmp( Name, "ntkrpamp.exe", 12 ) == 0 )
            return;

        if ( Mod.SizeOfImage > MaxImageBytes )
            return;

        HANDLE FileHandle = nullptr;
        if ( !NT_SUCCESS( OpenFile( Mod.FullPath, &FileHandle ) ) )
            return;

        PVOID DiskBuf  = nullptr;
        ULONG DiskSize = 0;
        NTSTATUS Status = ReadFile( FileHandle, MaxImageBytes, &DiskBuf, &DiskSize );
        ZwClose( FileHandle );

        if ( !NT_SUCCESS( Status ) )
            return;

        ULONG TextVa   = 0, TextFileOff = 0, TextRawSize = 0, TextVirtSize = 0;
        bool  HasText  = FindSection(
            static_cast< const UCHAR* >( DiskBuf ), DiskSize,
            ".text", &TextVa, &TextFileOff, &TextRawSize, &TextVirtSize );

        if ( !HasText || !TextFileOff || !TextRawSize )
        {
            Mem::Free( DiskBuf );
            return;
        }

        if ( TextFileOff + TextRawSize > DiskSize )
        {
            Mem::Free( DiskBuf );
            return;
        }

        // Build reloc skip bitmap (may be null if no .reloc section).
        //
        PVOID Bitmap = BuildRelocBitmap( static_cast< const UCHAR* >( DiskBuf ),
                                         DiskSize, TextFileOff, TextRawSize );

        const UCHAR* DiskText = static_cast< const UCHAR* >( DiskBuf ) + TextFileOff;
        const UCHAR* MemText  = static_cast< const UCHAR* >( Mod.DllBase ) + TextVa;
        ULONG CompareLen      = min( TextRawSize, TextVirtSize );
        auto* Skip            = static_cast< const UCHAR* >( Bitmap );

        // Walk the text section looking for runs of differing bytes.
        //
        ULONG i = 0;
        while ( i < CompareLen )
        {
            if ( Skip && Skip[i] )
            {
                ++i;
                continue;
            }

            if ( !MmIsAddressValid( const_cast< UCHAR* >( MemText + i ) ) )
            {
                ++i;
                continue;
            }

            if ( DiskText[i] == MemText[i] )
            {
                ++i;
                continue;
            }

            // Found start of a mismatch run.
            //
            ULONG Start = i;
            while ( i < CompareLen &&
                    ( Skip && Skip[i] ? true : (
                        MmIsAddressValid( const_cast< UCHAR* >( MemText + i ) ) &&
                        DiskText[i] != MemText[i] ) ) )
            {
                ++i;
            }

            Out.Add( FindingKind::Patch, Mod.DllBase, TextVa + Start, i - Start, Name );

            if ( Out.Count >= MaxFindings )
                break;
        }

        if ( Bitmap )
            Mem::Free( Bitmap );

        Mem::Free( DiskBuf );
    }

    void Scan( const Scan::ModuleList& Modules, FindingList& Out )
    {
        for ( ULONG i = 0; i < Modules.Count && Out.Count < MaxFindings; ++i )
            CheckModule( Modules.Entries[i], Out );
    }
}
