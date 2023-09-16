#include "includes.h"
#include <unordered_map>

std::uintptr_t util::sig_scan( const char* signature, const uintptr_t module_base ) noexcept
{
    if ( !module_base )
        return 0;

    auto pattern_to_byte = [ ]( const char* pattern ) noexcept -> std::vector<int>
    {
        auto bytes = std::vector<int>{ };
        auto start = const_cast< char* >( pattern );
        auto end = const_cast< char* >( pattern ) + std::strlen( pattern );

        for ( auto current = start; current < end; ++current )
        {
            if ( *current == '?' )
            {
                ++current;

                if ( *current == '?' )
                    ++current;

                bytes.push_back( -1 );
            }
            else
                bytes.push_back( std::strtoul( current, &current, 16 ) );
        }

        return bytes;
    };

    auto dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( module_base );
    auto nt_headers =
        reinterpret_cast< PIMAGE_NT_HEADERS >( reinterpret_cast< std::uint8_t* >( module_base ) + dos_header->e_lfanew );

    auto size = nt_headers->OptionalHeader.SizeOfImage;
    auto bytes = pattern_to_byte( signature );
    auto scan_bytes = reinterpret_cast< std::uint8_t* >( module_base );

    auto s = bytes.size( );
    auto d = bytes.data( );

    for ( auto i = 0ul; i < size - s; ++i )
    {
        bool found = true;

        for ( auto j = 0ul; j < s; ++j )
        {
            if ( scan_bytes[ i + j ] != d[ j ] && d[ j ] != -1 )
            {
                found = false;
                break;
            }
        }

        if ( found )
            return reinterpret_cast< std::uintptr_t >( &scan_bytes[ i ] );
    }

    return 0;
}
