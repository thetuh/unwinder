#include "includes.h"
#include <unordered_map>

bool util::pattern_to_bytes( const char* pattern, std::vector<int>& bytes ) noexcept
{
    bytes.clear( );
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

    return bytes.size( );
}

std::uintptr_t util::sig_scan( const char* signature, const uintptr_t base, const uintptr_t end ) noexcept
{
    if ( !base )
        return 0;

    const DWORD size = end ? end - base : reinterpret_cast< PIMAGE_NT_HEADERS >( reinterpret_cast< std::uint8_t* >( base ) + reinterpret_cast< PIMAGE_DOS_HEADER >( base )->e_lfanew )->OptionalHeader.SizeOfImage;

    std::vector<int> bytes{ };
    pattern_to_bytes( signature, bytes );

    auto scan_bytes = reinterpret_cast< std::uint8_t* >( base );

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