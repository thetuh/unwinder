#pragma once

/*
* @https://www.youtube.com/watch?v=dl-AuN2xsbg&ab_channel=x33fcon
* ------------------------------------------------------------
* about the Exception directory
* ------------------------------------------------------------
*
* "For each program, the compiler automatically creates a section called pdata that contains all the instructions that are relevant to a
* specific function prologue.
*
* Why the prologue? Because as we said, RSP is static through the body so all the information related to the stack frame size is a direct result
* of the operations performed in a prologue of a function.
*
* Within the pdata section is contained the Exception Directory. This directory maintains a RUNTIME_FUNCTION table with a list of all these runtime functions.
*
* ------------------------------------------------------------
* about the Unwind algorithm
* ------------------------------------------------------------
*
* "The RUNTIME_FUNCTION structure contains the begin address of the function, the end address of the function, and an image base relative address called UnwindData/UnwindInfoAddress
* that leads to the UnwindInfo structure which contains (among other things) the UnwindCode array. The UnwindCode array is the list of instructions that are performed within
* the prologue of a function.
*
* Why this is important is if we loop through all these UnwindCode structures, based on the OpInfo and the OpCode, we can understand all the
* operations that had an impact on the stack.
*
* In other words, if we loop through all of these, we can dynamically detect a stack frame size. Once we detect the stack frame size, we can
* locate the return address, get the return address, and repeat this process for each of the previous stack frames. This is the Unwind algorithm."
*/

namespace uw
{
	namespace internal
	{
		void translate_register( UBYTE op_info, char* register_name );
		bool load_process_symbols( const HANDLE process );
	}

	enum log
	{
		LOG_DISABLED = ( 1 << 0 ), /* don't print anything (default) */
		LOG_RESULTS = ( 1 << 1 ), /* print output info and errors */
		LOG_OPCODES = ( 1 << 2 ), /* print unwind operations */
		LOG_VERBOSE = ( LOG_RESULTS | LOG_OPCODES )
	};

	struct operation
	{
		UBYTE op_code;
		UBYTE op_register;
		
		/* reserved for output */
		DWORD64 offset;
	};

	struct sig_scan
	{
		enum address_type
		{
			DIRECT_ADDRESS, /* return addresss of gadget instruction */
			FUNCTION_ADDRESS /* return address of the function that the gadget resides in */
		};

		const char* pattern;
		address_type return_type = DIRECT_ADDRESS;
	};


	/*
	* unwinds entries in the runtime function table through emulation of RtlVirtualUnwind.
	* can be used to search for a function with a specific signature or unwind operation.
	* 
	* @param [in] base address of module/process
	* @param [in, optional] base address of function
	* @param [in, optional] logging
	* @param [in, out, optional] stack size
	* @param [in, out, optional] desired uwop
	* @param [in, optional] signature to scan
	* 
	* @return address of function, if found to meet search parameters
	*/
	uintptr_t query_unwind_info( const uintptr_t image_base, const uintptr_t* function_address = nullptr, const log logging = log::LOG_DISABLED, DWORD64* stack_size = nullptr, operation* uwop = nullptr, const sig_scan* signature_scan = nullptr );

	/* walks the callstack of the running thread (doesn't integrity check) */
	void stack_walk( );

	/* walks the callstack of a specified <process_id, thread_id> pair */
	void stack_walk( const DWORD pid, const DWORD tid );

	/* walks the callstack of a specified <process_handle, thread_handle> pair */
	void stack_walk( const HANDLE process, const HANDLE thread );
}