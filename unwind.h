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

namespace unwind
{
	enum log
	{
		LOG_DISABLED,
		LOG_ERRORS,
		LOG_OPCODES,
		LOG_VERBOSE = ( LOG_ERRORS | LOG_OPCODES )
	};

	DWORD64 calculate_stack_size( const uintptr_t image_base, const char* export_name, const log logging = log::LOG_DISABLED );
	DWORD64 calculate_stack_size( const uintptr_t image_base, const uintptr_t function_address, const log logging = log::LOG_DISABLED, const char* function_name = "function" );
}