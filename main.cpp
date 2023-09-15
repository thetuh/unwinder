#include "includes.h"

#ifdef _DEBUG
uint64_t add2( uint64_t a, uint64_t b, uint64_t c )
{
	return a + b + c;
}

uint64_t add(  )
{
	uint64_t a = 100;
	uint64_t b = 200;
	uint64_t c = 300;

	uint64_t result = 0;
	result = add2( a, b, c );

	uintptr_t retaddr = ( uintptr_t ) _ReturnAddress( );
	printf( "0x%p\n", retaddr );

	return result;
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

	const auto kernel32_base = ( uintptr_t ) GetModuleHandleA( "kernel32" );
	const auto ntdll_base = ( uintptr_t ) GetModuleHandleA( "ntdll" );

	if ( unwind::calculate_stack_size( kernel32_base, ( uintptr_t ) GetProcAddress( ( HMODULE ) kernel32_base, "BaseThreadInitThunk"), unwind::LOG_VERBOSE, "BaseThreadInitThunk" ) != BaseThreadInitThunkStackSize )
		return terminate( "incorrect BaseThreadInitThunk stack size" );

	if ( unwind::calculate_stack_size( ntdll_base, ( uintptr_t ) GetProcAddress( ( HMODULE ) ntdll_base, "RtlUserThreadStart"), unwind::LOG_VERBOSE, "RtlUserThreadStart" ) != RtlUserThreadStartStackSize )
		return terminate( "incorrect RtlUserThreadStart stack size" );

	/* these get optimized out in release mode */
#ifdef _DEBUG
	const auto process_base = ( uintptr_t ) GetModuleHandleA( NULL );
	const auto add_address = RVA( ( uintptr_t ) add, 5 );
	const auto add2_address = RVA( ( uintptr_t ) add2, 5 );

	if ( unwind::calculate_stack_size( process_base, add_address, unwind::LOG_VERBOSE, "add" ) != AddStackSize )
		return terminate( "incorrect add stack size" );

	if ( unwind::calculate_stack_size( process_base, add2_address, unwind::LOG_VERBOSE, "add2" ) != Add2StackSize )
		return terminate( "incorrect add2 stack size" );
#endif


	return terminate( "success", true );
}