#include "includes.h"

int main( )
{
	const auto terminate = [ & ]( const char* msg, const bool success = false ) -> int
	{
		success ? printf( "[main] %s\n", msg ) : printf( "[main] error: %s\n", msg );
		getchar( );
		return success ? 0 : 1;
	};

	const auto kernel32_base = ( uintptr_t ) GetModuleHandleA( "kernel32" );
	if ( !kernel32_base )
		return terminate( "kernel32.dll not found" );

	const auto ntdll_base = ( uintptr_t ) GetModuleHandleA( "ntdll" );
	if ( !ntdll_base )
		return terminate( "ntdll.dll not found" );

	const auto base_init_thread_thunk = ( uintptr_t ) GetProcAddress( ( HMODULE ) kernel32_base, "BaseThreadInitThunk" );
	const auto rtl_user_thread_start = ( uintptr_t ) GetProcAddress( ( HMODULE ) ntdll_base, "RtlUserThreadStart" );
	
	printf( "-------------------------------------\nperforming tests\n-------------------------------------\n" );
	{
		DWORD64 stack_size{ };

		if ( !uw::virtual_unwind( kernel32_base, &base_init_thread_thunk, uw::LOG_RESULTS, "BaseThreadInitThunk", &stack_size ) )
			return terminate( "virtual_unwind failed for BaseThreadInitThunk" );

		if ( stack_size != BaseThreadInitThunkStackSize )
			return terminate( "incorrect BaseThreadInitThunkStackSize stack size resolve" );

		if ( !uw::virtual_unwind( ntdll_base, &rtl_user_thread_start, uw::LOG_RESULTS, "RtlUserThreadStart", &stack_size ) )
			return terminate( "virtual_unwind failed for RtlUserThreadStart" );

		if ( stack_size != RtlUserThreadStartStackSize )
			return terminate( "incorrect RtlUserThreadStart stack size resolve" );
	}
	printf( "tests succeeded\n-------------------------------------\n" );

	uw::operation uwop{ };

	/* first frame (mov rbp, rsp) */

	const auto kernelbase = ( uintptr_t ) GetModuleHandleA( "kernelbase" );
	if ( !kernelbase )
		return terminate( "kernelbase.dll not found" );

	DWORD64 f1_stack_size{ };
	uwop.op_code = UWOP_SET_FPREG;
	uwop.op_register = RBP;

	const auto f1_addresss = uw::virtual_unwind( kernelbase, nullptr, uw::LOG_DISABLED, nullptr, &f1_stack_size, &uwop );
	if ( !f1_addresss )
		return terminate( "could not locate first frame" );

	printf( "first frame address: 0x%p\n", f1_addresss );
	printf( "first frame stack size: %llu\n", f1_stack_size );

	/* second frame (push rbp) */

	DWORD64 f2_stack_size{ };
	uwop.op_code = UWOP_PUSH_NONVOL;
	uwop.op_register = RBP;

	const auto f2_address = uw::virtual_unwind( kernelbase, nullptr, uw::LOG_DISABLED, nullptr, &f2_stack_size, &uwop );
	if ( !f2_address )
		return terminate( "could not locate second frame" );

	printf( "second frame address: 0x%p\n", f2_address );
	printf( "second frame stack size: %llu\n", f2_stack_size );

	/* third frame (jmp rbx gadget) */

	uw::sig_scan gadget_sig{ };
	gadget_sig.pattern = "FF 23";
	gadget_sig.return_type = uw::sig_scan::DIRECT_ADDRESS;

	DWORD64 gadget_stack_size{ };
	const auto gadget = uw::virtual_unwind( kernelbase, nullptr, uw::LOG_DISABLED, nullptr, &gadget_stack_size, nullptr, &gadget_sig );
	if ( !gadget )
		return terminate( "gadget not found" );

	printf( "gadget address: 0x%p\n", gadget );
	printf( "stack size: %llu\n", gadget_stack_size );

	/* fourth frame (add rsp) */

	uw::sig_scan gadget2_sig{ };
	gadget2_sig.pattern = "48 83 C4 38 C3";
	gadget2_sig.return_type = uw::sig_scan::DIRECT_ADDRESS;

	DWORD64 gadget2_stack_size{ };
	const auto gadget2 = uw::virtual_unwind( kernelbase, nullptr, uw::LOG_DISABLED, nullptr, &gadget2_stack_size, nullptr, &gadget2_sig );
	if ( !gadget2 )
		return terminate( "gadget2 not found" );

	printf( "gadget address: 0x%p\n", gadget2 );
	printf( "stack size: %llu\n", gadget2_stack_size );

	return terminate( "success", true );
}