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
	
	printf( "performing tests\n-------------------------------------\n" );
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

	if ( !uw::virtual_unwind( kernelbase, nullptr, uw::LOG_RESULTS, nullptr, &f1_stack_size, &uwop ) )
		return terminate( "could not locate first frame" );

	/* second frame (push rbp) */

	DWORD64 f2_stack_size{ };
	uwop.op_code = UWOP_PUSH_NONVOL;
	uwop.op_register = RBP;

	if ( !uw::virtual_unwind( kernelbase, nullptr, uw::LOG_RESULTS, nullptr, &f2_stack_size, &uwop ) )
		return terminate( "could not locate second frame" );

	/* third frame (jmp rbx gadget) */

	const auto jmp_rbx =  util::sig_scan( "FF 23", kernelbase );
	if ( !jmp_rbx )
		return terminate( "could not locate jmp rbx gadget" );

	printf( "0x%p\n", jmp_rbx );

	return terminate( "success", true );
}