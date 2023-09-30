#include "includes.h"

int main( )
{
	const auto terminate = [ & ]( const char* msg, const bool success = false ) -> int
	{
		success ? printf( "[main] %s\n", msg ) : printf( "[main] error: %s\n", msg );
		getchar( );
		return success ? 0 : 1;
	};

	if ( !util::set_privilege( L"SeDebugPrivilege", TRUE ) )
		return terminate( "could not set privilege" );

	const auto kernelbase = ( uintptr_t ) GetModuleHandleA( "kernelbase" );
	if ( !kernelbase )
		return terminate( "kernelbase.dll not found" );

	const auto kernel32_base = ( uintptr_t ) GetModuleHandleA( "kernel32" );
	if ( !kernel32_base )
		return terminate( "kernel32.dll not found" );

	const auto ntdll_base = ( uintptr_t ) GetModuleHandleA( "ntdll" );
	if ( !ntdll_base )
		return terminate( "ntdll.dll not found" );

	const auto user32_base = ( uintptr_t ) LoadLibraryA( "user32.dll" );
	if ( !user32_base )
		return terminate( "user32.dll not found" );

	const auto base_init_thread_thunk = ( uintptr_t ) GetProcAddress( ( HMODULE ) kernel32_base, "BaseThreadInitThunk" );
	const auto rtl_user_thread_start = ( uintptr_t ) GetProcAddress( ( HMODULE ) ntdll_base, "RtlUserThreadStart" );
	const auto message_box_a = ( uintptr_t ) GetProcAddress( ( HMODULE ) user32_base, "MessageBoxA" );

	DWORD64 ss1{ };
	if ( !uw::query_unwind_info( kernel32_base, &base_init_thread_thunk, uw::LOG_VERBOSE, &ss1 ) )
		return terminate( "virtual_unwind failed for BaseThreadInitThunk" );

	DWORD64 ss2{ };
	if ( !uw::query_unwind_info( ntdll_base, &rtl_user_thread_start, uw::LOG_VERBOSE, &ss2 ) )
		return terminate( "virtual_unwind failed for RtlUserThreadStart" );

	DWORD64 ss3{ };
	if ( !uw::query_unwind_info( user32_base, &message_box_a, uw::LOG_VERBOSE, &ss3 ) )
		return terminate( "virtual_unwind failed for MessageBoxA" );

	uw::operation uwop{ };

	/*
	* ---------------------------------------------------------
	* mov rbp, rsp
	* ---------------------------------------------------------
	*/

	uwop.op_code = UWOP_SET_FPREG;
	uwop.op_register = RBP;

	DWORD64 mov_rbp_rsp_size{ };
	const auto mov_rbp_rsp{ uw::query_unwind_info( kernelbase, nullptr, uw::LOG_VERBOSE, &mov_rbp_rsp_size, &uwop ) };
	if ( !mov_rbp_rsp )
		return terminate( "mov rbp, rsp not found" );

	/*
	* ---------------------------------------------------------
	* push rbp
	* ---------------------------------------------------------
	*/

	uwop.op_code = UWOP_PUSH_NONVOL;
	uwop.op_register = RBP;

	DWORD64 push_rbp_size{ };
	const auto push_rbp{ uw::query_unwind_info( kernelbase, nullptr, uw::LOG_VERBOSE, &push_rbp_size, &uwop ) };
	if ( !push_rbp )
		return terminate( "push rbp not found" );

	const auto push_rbp_offset = uwop.offset;

	/*
	* ---------------------------------------------------------
	* jmp rbx
	* ---------------------------------------------------------
	*/

	uw::sig_scan gadget_sig{ };
	gadget_sig.pattern = "FF 23";
	gadget_sig.return_type = uw::sig_scan::DIRECT_ADDRESS;

	DWORD64 gadget_size{ };
	const auto gadget{ uw::query_unwind_info( kernelbase, nullptr, uw::LOG_VERBOSE, &gadget_size, nullptr, &gadget_sig ) };
	if ( !gadget )
		return terminate( "jmp rbx not found" );

	spoof_info config{ };
	config.add_rsp_gadget = ( PVOID ) ( message_box_a + 0x4e );
	config.add_rsp_gadget_frame_size = ss3;
	config.arbitrary_frame = ( PVOID ) ( rtl_user_thread_start + 0x21 );
	config.arbitrary_frame_size = ss2;
	config.target_function = ( PVOID ) MessageBoxA;
	config.return_address = ( PVOID ) _AddressOfReturnAddress( );
	config.push_rbp_offset = push_rbp_offset;
	config.set_fpreg_frame = ( PVOID ) ( mov_rbp_rsp );
	config.set_fpreg_frame_size = mov_rbp_rsp_size;
	config.push_rbp_frame = ( PVOID ) ( push_rbp );
	config.push_rbp_frame_size = push_rbp_size;
	config.jmp_rbx_gadget = ( PVOID ) gadget;
	config.jmp_rbx_gadget_frame_size = gadget_size;
	config.arg1 = ( PVOID ) NULL;
	config.arg2 = ( PVOID ) "spoofed call";
	config.arg3 = ( PVOID ) "title";
	config.arg4 = ( PVOID ) MB_OK;

	auto spoofed_thread = std::thread( &experimental_spoof, &config );
	const auto tid = GetThreadId( spoofed_thread.native_handle( ) );
	spoofed_thread.detach( );

	getchar( );

	const HANDLE thread_snapshot{ CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ) };
	if ( thread_snapshot == INVALID_HANDLE_VALUE )
		return terminate( "could not retrieve open thread snapshot" );

	THREADENTRY32 thread_entry{ };
	thread_entry.dwSize = sizeof( THREADENTRY32 );

	if ( Thread32First( thread_snapshot, &thread_entry ) )
		do { uw::stack_walk( thread_entry.th32OwnerProcessID, thread_entry.th32ThreadID ); } while ( Thread32Next( thread_snapshot, &thread_entry ) );

	CloseHandle( thread_snapshot );

	return terminate( "success", true );
}