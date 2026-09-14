#include <Misc/Incl.h>
#include <Core/Identity/SMBIOS/Tables/Tables.h>

namespace Tables
{

    const char* GetString( const UCHAR* Struct, UCHAR Index, const UCHAR* TableEnd )
    {
        if ( !Index )
            return nullptr;

        const char* Ptr = reinterpret_cast< const char* >( Struct + Struct[1] );
        const char* End = reinterpret_cast< const char* >( TableEnd );

        // Walk 1-based string list until we reach the requested index.
        //
        for ( UCHAR I = 1; I < Index; ++I )
        {
            while ( Ptr < End && *Ptr )
                ++Ptr;

            if ( Ptr >= End )
                return nullptr;

            ++Ptr;

            // Consecutive null byte means the string section ended.
            //
            if ( !*Ptr )
                return nullptr;
        }

        return ( *Ptr && Ptr < End ) ? Ptr : nullptr;
    }

    const UCHAR* NextStruct( const UCHAR* Struct, const UCHAR* TableEnd )
    {
        const UCHAR* Ptr = Struct + Struct[1];

        // Scan for the double-null terminator that ends the string section.
        //
        while ( Ptr + 1 < TableEnd )
        {
            if ( Ptr[0] == 0 && Ptr[1] == 0 )
                return Ptr + 2;

            ++Ptr;
        }

        return nullptr;
    }

    static bool StrEq( const char* A, const char* B )
    {
        while ( *A && *A == *B ) { ++A; ++B; }
        return *A == *B;
    }

    bool IsJunk( const char* Str )
    {
        if ( !Str || !*Str )
            return true;

        static const char* const Placeholders[] = {
            "To Be Filled By O.E.M.",
            "Default string",
            "Not Specified",
            "Unknown",
            "System Serial Number",
            "Base Board Serial Number",
            "Chassis Serial Number",
            "0123456789",
            "None",
            "N/A",
            "NA",
            "OEM Default String",
            "Type2 - Board Serial Number",
            "Type1ProductConfigId",
            "Type3 - Chassis Serial Number",
        };

        for ( auto* P : Placeholders )
        {
            if ( StrEq( Str, P ) )
                return true;
        }

        return false;
    }

}
