#include "includes.h"
#include <unordered_map>

bool util::set_privilege( LPCWSTR privilege, BOOL enable_privilege )
{
    TOKEN_PRIVILEGES priv = { 0,0,0,0 };
    HANDLE token = NULL;
    LUID luid = { 0,0 };
    if ( !OpenProcessToken( GetCurrentProcess( ), TOKEN_ADJUST_PRIVILEGES, &token ) )
    {
        if ( token )
            CloseHandle( token );
        return false;
    }
    if ( !LookupPrivilegeValueW( 0, privilege, &luid ) )
    {
        if ( token )
            CloseHandle( token );
        return false;
    }
    priv.PrivilegeCount = 1;
    priv.Privileges[ 0 ].Luid = luid;
    priv.Privileges[ 0 ].Attributes = enable_privilege ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
    if ( !AdjustTokenPrivileges( token, false, &priv, 0, 0, 0 ) )
    {
        if ( token )
            CloseHandle( token );
        return false;
    }
    if ( token )
        CloseHandle( token );
    return true;
}

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

    const DWORD size = end ? DWORD( end - base ) : reinterpret_cast< PIMAGE_NT_HEADERS >( reinterpret_cast< std::uint8_t* >( base ) + reinterpret_cast< PIMAGE_DOS_HEADER >( base )->e_lfanew )->OptionalHeader.SizeOfImage;

    std::vector<int> bytes{ };
    pattern_to_bytes( signature, bytes );

    auto scan_bytes = reinterpret_cast< std::uint8_t* >( base );
    auto s = bytes.size( );
    if ( size < s )
        return 0;

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