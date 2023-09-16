#include "includes.h"

#ifdef _DEBUG
uint64_t add(  )
{
	uint64_t a = 100;
	uint64_t b = 200;
	uint64_t c = 300;

	uint64_t result = 0;
    result = a + b + c;

	uintptr_t retaddr = ( uintptr_t ) _ReturnAddress( );

	return result;
}

std::uintptr_t sig_scan( const char* signature, const char* module_name ) noexcept
{
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

    const HANDLE handle = GetModuleHandleA( module_name );
    if ( !handle )
        return 0;

    auto dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( handle );
    auto nt_headers =
        reinterpret_cast< PIMAGE_NT_HEADERS >( reinterpret_cast< std::uint8_t* >( handle ) + dos_header->e_lfanew );

    auto size = nt_headers->OptionalHeader.SizeOfImage;
    auto bytes = pattern_to_byte( signature );
    auto scan_bytes = reinterpret_cast< std::uint8_t* >( handle );

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
#endif

int main( )
{
	const auto terminate = [ & ]( const char* msg, const bool success = false ) -> int
	{
		success ? printf( "[main] %s\n", msg ) : printf( "[main] error: %s\n", msg );
		getchar( );
		return success ? 0 : 1;
	};

	/* get rid of annoying C6387 warnings */
	const auto kernel32_base = ( uintptr_t ) GetModuleHandleA( "kernel32" );
	if ( !kernel32_base )
		return terminate( "kernel32.dll not found" );

	const auto ntdll_base = ( uintptr_t ) GetModuleHandleA( "ntdll" );
	if ( !ntdll_base )
		return terminate( "ntdll.dll not found" );

    const auto base_init_thread_thunk = ( uintptr_t ) GetProcAddress( ( HMODULE ) kernel32_base, "BaseThreadInitThunk" );
    const auto rtl_user_thread_start = ( uintptr_t ) GetProcAddress( ( HMODULE ) ntdll_base, "RtlUserThreadStart" );

    if ( !uw::virtual_unwind( kernel32_base, &base_init_thread_thunk, uw::LOG_VERBOSE, "BaseThreadInitThunk" ) )
        return terminate( "virtual_unwind failed for BaseThreadInitThunk" );

    if ( !uw::virtual_unwind( ntdll_base, &rtl_user_thread_start, uw::LOG_VERBOSE, "RtlUserThreadStart" ) )
        return terminate( "virtual_unwind failed for RtlUserThreadStart" );

	/* these get optimized out in release mode */
#ifdef _DEBUG
    const auto process_base = ( uintptr_t ) GetModuleHandleA( NULL );
	const auto add_address = RVA( ( uintptr_t ) add, 5 );
	const auto sig_scan_address = RVA( ( uintptr_t ) sig_scan, 5 );

    DWORD64 stack_size{ };
    DWORD64 return_address_offset{ };

    /* test stack size/return address offset detection */

    if ( !uw::virtual_unwind( process_base, &add_address, uw::LOG_VERBOSE, "add", &stack_size, &return_address_offset ) )
        return terminate( "virtual_unwind failed for add" );

    if ( stack_size != AddStackSize || return_address_offset != AddReturnAddressOffset )
        return terminate( "incorrect unwind for add" );

    if ( !uw::virtual_unwind( process_base, &sig_scan_address, uw::LOG_VERBOSE, "sig_scan", &stack_size, &return_address_offset ) )
        return terminate( "virtual_unwind failed for sig_scan" );

    if ( stack_size != SigScanStackSize || return_address_offset != SigScanReturnAddressOffset )
        return terminate( "incorrect unwind for sig_scan" );

    /* test uwop detection */

    uw::operation uwop{ };
    uwop.op_code = UWOP_PUSH_NONVOL;
    uwop.op_register = RBP;

    if ( !uw::virtual_unwind( process_base, &add_address, uw::LOG_VERBOSE, "add", nullptr, nullptr, &uwop ) )
        return terminate( "incorrect uwop add" );

    uwop.op_register = RBP;

    if ( !uw::virtual_unwind( process_base, &sig_scan_address, uw::LOG_VERBOSE, "add", nullptr, nullptr, &uwop ) )
        return terminate( "incorrect uwop add" );

#endif

	return terminate( "success", true );
}