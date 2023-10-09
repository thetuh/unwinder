#include "includes.h"

#include "Zydis.h"

bool in_valid_module( const uintptr_t address, const DWORD pid )
{
	const HANDLE snapshot{ CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pid ) };
	if ( snapshot == INVALID_HANDLE_VALUE )
		return true;

	MODULEENTRY32 module_entry{ };
	module_entry.dwSize = sizeof( MODULEENTRY32 );

	if ( Module32First( snapshot, &module_entry ) )
	{
		do
		{
			if ( address >= ( uintptr_t ) module_entry.modBaseAddr && address < ( ( uintptr_t ) module_entry.modBaseAddr + ( uintptr_t ) module_entry.modBaseSize ) )
			{
				CloseHandle( snapshot );
				return true;
			}
		} while ( Module32Next( snapshot, &module_entry ) );
	}

	CloseHandle( snapshot );
	return false;
}

void uw::internal::translate_register( UBYTE op_info, char* register_name )
{
	switch ( op_info )
	{
		case R12:
		{
			strcpy_s( register_name, 4, "R12" );
			break;
		}
		case R13:
		{
			strcpy_s( register_name, 4, "R13" );
			break;
		}
		case R14:
		{
			strcpy_s( register_name, 4, "R14" );
			break;
		}
		case R15:
		{
			strcpy_s( register_name, 4, "R15" );
			break;
		}
		case RDI:
		{
			strcpy_s( register_name, 4, "RDI" );
			break;
		}
		case RSI:
		{
			strcpy_s( register_name, 4, "RSI" );
			break;
		}
		case RBX:
		{
			strcpy_s( register_name, 4, "RBX" );
			break;
		}
		case RBP:
		{
			strcpy_s( register_name, 4, "RBP" );
			break;
		}
		case RSP:
		{
			strcpy_s( register_name, 4, "RSP" );
			break;
		}
		default:
		{
			strcpy_s( register_name, 4, "???" );
			break;
		}
	}
}

bool uw::internal::load_process_symbols( const HANDLE process )
{
	DWORD options = SymGetOptions( );
	options |= SYMOPT_LOAD_LINES | SYMOPT_UNDNAME;
	SymSetOptions( options );

	if ( !SymInitialize( process, NULL, TRUE ) )
	{
		printf( "SymInitialize failed, error 0x%p\n", GetLastError( ) );
		return false;
	}

	MODULEINFO module_info = { 0 };
	if ( GetModuleInformation( process, NULL, &module_info, sizeof( module_info ) ) )
		SymLoadModuleEx( process, NULL, NULL, NULL, ( DWORD64 ) module_info.lpBaseOfDll, module_info.SizeOfImage, NULL, 0 );
	else
		printf( "GetModuleInformation failed, error 0x%p\n", GetLastError( ) );

	return true;
}

void uw::stack_walk( )
{
	SymInitialize( GetCurrentProcess( ), nullptr, TRUE );

	constexpr auto MAX_FRAMES = 64;
	PVOID stack_frames[ MAX_FRAMES ];
	const auto captured_frames = RtlCaptureStackBackTrace( 0, MAX_FRAMES, stack_frames, NULL );

	CHAR process_name[ MAX_PATH ];
	GetModuleFileNameA( NULL, process_name, MAX_PATH );
	printf( "stack walk (%s, pid:%lu, tid:%lu)\n", strrchr( process_name, '\\' ) + 1, GetCurrentProcessId( ), GetCurrentThreadId( ) );

	for ( WORD i = 0; i < captured_frames; i++ )
	{
		const auto frame_return_address = DWORD64( stack_frames[ i ] );
		if ( !frame_return_address )
			break;

		IMAGEHLP_MODULE64 module_info = { sizeof( IMAGEHLP_MODULE64 ) };
		if ( SymGetModuleInfo64( GetCurrentProcess( ), frame_return_address, &module_info ) )
		{
			BYTE buffer[ sizeof( SYMBOL_INFO ) + MAX_SYM_NAME * sizeof( TCHAR ) ];
			const PSYMBOL_INFO symbol = ( PSYMBOL_INFO ) buffer;
			symbol->SizeOfStruct = sizeof( SYMBOL_INFO );
			symbol->MaxNameLen = MAX_SYM_NAME;

			DWORD64 displacement{ };
			if ( SymFromAddr( GetCurrentProcess( ), frame_return_address, &displacement, symbol ) )
				printf( " %hu, %s!%s+0x%llx\n", i, ( strrchr( module_info.ImageName, '\\' ) + 1 ), symbol->Name, displacement );
			else
				printf( " %hu, %s+0x%llx\n", i, ( strrchr( module_info.ImageName, '\\' ) + 1 ), ( frame_return_address - module_info.BaseOfImage ) );
		}
		else
		{
			printf( " %hu, 0x%llx\n", i, frame_return_address );
		}
	}

	printf( "-------------------------------------\n" );

	SymCleanup( GetCurrentProcess( ) );
}

void uw::stack_walk( const DWORD pid, const DWORD tid, const log logging )
{
	static std::unordered_set<DWORD>blacklisted_pids;
	if ( blacklisted_pids.find( pid ) != blacklisted_pids.end( ) )
		return;

	const HANDLE process = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
	if ( !process )
	{
		printf( "[stack_walk] error: failed to open process handle (pid: %lu)\n-------------------------------------\n", pid );
		blacklisted_pids.insert( pid );
		return;
	}

	const HANDLE thread = OpenThread( THREAD_ALL_ACCESS, FALSE, tid );
	if ( !thread )
	{
		printf( "[stack_walk] error: failed to open thread handle\n-------------------------------------\n" );
		CloseHandle( process );
		return;
	}

	stack_walk( process, thread, logging );
	CloseHandle( thread );
	CloseHandle( process );
}

void uw::stack_walk( const HANDLE process, const HANDLE thread, const log logging )
{
	CHAR process_name[ MAX_PATH ];
	GetModuleFileNameExA( process, NULL, process_name, MAX_PATH );
	printf( "stack walk (%s, pid:%lu, tid:%lu)\n", strrchr( process_name, '\\' ) + 1, GetProcessId( process ), GetThreadId( thread ) );

	CONTEXT context{ };
	context.ContextFlags = CONTEXT_FULL;

	if ( !GetThreadContext( thread, &context ) )
	{
		printf( "[stack_walk] error: failed to get thread context\n-------------------------------------\n" );
		return;
	}

	if ( !internal::load_process_symbols( process ) )
	{
		printf( "[stack_walk] error: failed to load process symbols\n-------------------------------------\n" );
		return;
	}

	ZydisDecoder decoder;
	ZydisDecoderInit( &decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64 );
	ZydisDecodedInstruction instruction;

	STACKFRAME64 stack_frame{ };

	stack_frame.AddrPC.Mode = AddrModeFlat;
	stack_frame.AddrFrame.Mode = AddrModeFlat;
	stack_frame.AddrStack.Mode = AddrModeFlat;

	stack_frame.AddrPC.Offset = context.Rip;
	stack_frame.AddrFrame.Offset = context.Rsp;
	stack_frame.AddrStack.Offset = context.Rsp;

	WORD frame_count{ };
	bool unbacked_code{ false };
	bool invalid_call{ false };
	bool address_discrepancy{ false };

	uintptr_t last_function_address{ };

	std::vector<std::string> sw_logs{ };

	size_t raised_flags{ };

	while ( StackWalk64(
		IMAGE_FILE_MACHINE_AMD64,
		process,
		thread,
		&stack_frame,
		&context,
		NULL,
		SymFunctionTableAccess64,
		SymGetModuleBase64,
		NULL ) )
	{
		const auto frame_return_address = stack_frame.AddrPC.Offset;
		DWORD64 displacement{ };

		IMAGEHLP_MODULE64 module_info = { sizeof( IMAGEHLP_MODULE64 ) };
		if ( SymGetModuleInfo64( process, frame_return_address, &module_info ) )
		{
			BYTE buffer[ sizeof( SYMBOL_INFO ) + MAX_SYM_NAME * sizeof( TCHAR ) ];
			const PSYMBOL_INFO symbol = ( PSYMBOL_INFO ) buffer;
			symbol->SizeOfStruct = sizeof( SYMBOL_INFO );
			symbol->MaxNameLen = MAX_SYM_NAME;

			if ( SymFromAddr( process, frame_return_address, &displacement, symbol ) )
			{
				sw_logs.emplace_back( tfm::format( " %hu, %s!%s+0x%llx", frame_count, ( strrchr( module_info.ImageName, '\\' ) + 1 ), symbol->Name, displacement ) );
				// printf( " %hu, %s!%s+0x%llx", frame_count, ( strrchr( module_info.ImageName, '\\' ) + 1 ), symbol->Name, displacement );
			}
			else
			{
				sw_logs.emplace_back( tfm::format( " %hu, %s+0x%llx", frame_count, ( strrchr( module_info.ImageName, '\\' ) + 1 ), ( frame_return_address - module_info.BaseOfImage ) ) );
				// printf( " %hu, %s+0x%llx", frame_count, ( strrchr( module_info.ImageName, '\\' ) + 1 ), ( frame_return_address - module_info.BaseOfImage ) );
			}
		}
		else
		{
			sw_logs.emplace_back( tfm::format( " %hu, 0x%llx (invalid module)", frame_count, frame_return_address ) );
			// printf( " %hu, 0x%llx (invalid module)", frame_count, frame_return_address );
			unbacked_code = true;
		}

		{
			DWORD64 image_base{ };
			UNWIND_HISTORY_TABLE history_table{ };
			if ( const auto lookup_entr = RtlLookupFunctionEntry( frame_return_address, &image_base, &history_table ); lookup_entr )
				displacement = ( frame_return_address - image_base - lookup_entr->BeginAddress );
		}

		unsigned char instruction_buffer[ 8 ];
		if ( ReadProcessMemory( process, ( LPCVOID ) ( frame_return_address - 6 ), &instruction_buffer, 8, nullptr ) )
		{
			ZydisDecodedOperand operands[ ZYDIS_MAX_OPERAND_COUNT ];
			if ( ZYAN_SUCCESS( ZydisDecoderDecodeFull( &decoder, instruction_buffer, 7, &instruction, operands ) ) && instruction.mnemonic == ZYDIS_MNEMONIC_CALL )
			{
				static auto base_thread_init_thunk = ( uintptr_t ) GetProcAddress( GetModuleHandleA( "kernel32" ), "BaseThreadInitThunk" );
				static auto rtl_user_thread_start = ( uintptr_t ) GetProcAddress( GetModuleHandleA( "ntdll" ), "RtlUserThreadStart" );

				/* no reliable way of checking this function (that i know of) */
				if ( frame_return_address == base_thread_init_thunk + 0x14 )
				{
					last_function_address = base_thread_init_thunk;
					frame_count++;
					sw_logs.emplace_back( tfm::format("\n") );
					continue;
				}

				uintptr_t absolute_address{ };
				ZydisCalcAbsoluteAddress( &instruction, operands, frame_return_address - 6, &absolute_address );

				/* hardcoded check for RtlUserThreadStart */
				uintptr_t called_address;
				if ( ReadProcessMemory( process, ( LPCVOID ) ( absolute_address ), &called_address, sizeof( uintptr_t ), nullptr ) )
				{
					unsigned char instruction_buffer_2[ 6 ];
					if ( ReadProcessMemory( process, ( LPCVOID ) called_address, &instruction_buffer_2, 6, nullptr ) && instruction_buffer_2[ 0 ] == 0xFF )
					{
						if ( instruction_buffer_2[ 1 ] == 0xE0 && frame_return_address == ( uintptr_t ) rtl_user_thread_start + 0x21 )
						{
							const auto buffer{ std::make_unique<uint8_t[ ]>( displacement ) };
							if ( ReadProcessMemory( process, ( LPCVOID ) ( frame_return_address - displacement ), buffer.get( ), displacement, nullptr ) )
							{
								DWORD rip{ };
								DWORD rip_offset{ };
								for ( ULONG i = 0; i < displacement; i++ )
								{
									if ( buffer[ i ] == 0x48 && buffer[ i + 1 ] == 0x8B && buffer[ i + 2 ] == 0x05 )
									{
										rip_offset = *( DWORD* ) ( buffer.get( ) + i + 3 );
										rip = i + 7;
									}
								}

								if ( ReadProcessMemory( process, ( LPCVOID ) ( frame_return_address - displacement + rip + rip_offset ), &called_address, sizeof( void* ), nullptr ) )
								{
									if ( last_function_address != ( uintptr_t ) called_address )
									{
										raised_flags++;
										address_discrepancy = true;
										sw_logs.emplace_back( " (call address doesn't match)" );
										// printf( " (call address doesn't match)" );
									}
								}
							}
						}
					}
				}
				
				 // printf( " (previous instruction is a call)" );
			}
			else if ( ZYAN_SUCCESS( ZydisDecoderDecodeFull( &decoder, instruction_buffer + 1, 5, &instruction, operands ) ) && instruction.mnemonic == ZYDIS_MNEMONIC_CALL )
			{
				uintptr_t absolute_address{ };
				if ( ZYAN_SUCCESS( ZydisCalcAbsoluteAddress( &instruction, operands, frame_return_address - 5, &absolute_address ) ) )
				{
					uintptr_t image_base{ };
					UNWIND_HISTORY_TABLE history_table{ };
					const auto function_entry = RtlLookupFunctionEntry( ( uintptr_t ) absolute_address, &image_base, &history_table );
					if ( function_entry && ( function_entry->BeginAddress + image_base ) != last_function_address )
					{
						/* call address doesn't match, fall back to checking if both functions operate within the same stack frame */
						DWORD64 stack_size{ };
						if ( query_unwind_info( image_base, &last_function_address, LOG_DISABLED, &stack_size ) )
						{
							if ( stack_size )
							{
								raised_flags++;
								address_discrepancy = true;
								sw_logs.emplace_back( " (call address doesn't match)" );
								// printf( " (call address doesn't match)" );
							}
						}
						else
						{
							raised_flags++;
							address_discrepancy = true;
							sw_logs.emplace_back( " (call address doesn't match)" );
							// printf( " (call address doesn't match)" );
						}
					}
				}

				 // printf( " (previous instruction is a relative call)" );
			}
			else if ( ZYAN_SUCCESS( ZydisDecoderDecodeFull( &decoder, instruction_buffer + 4, 2, &instruction, operands ) ) && instruction.mnemonic == ZYDIS_MNEMONIC_SYSCALL )
			{
				// printf( " (previous instruction is a syscall)" );
			}
			else if ( ( ZYAN_SUCCESS( ZydisDecoderDecodeFull( &decoder, instruction_buffer + 3, 3, &instruction, operands ) ) && instruction.mnemonic == ZYDIS_MNEMONIC_CALL ) ||
				( ZYAN_SUCCESS( ZydisDecoderDecodeFull( &decoder, instruction_buffer + 4, 2, &instruction, operands ) ) && instruction.mnemonic == ZYDIS_MNEMONIC_CALL ) )
			{
				// sw_logs.emplace_back( " (previous instruction is a general-purpose register call)" );
				// printf( " (previous instruction is a general-purpose register call)" );
			}
			else
			{
				raised_flags++;
				sw_logs.emplace_back( " (no call found)" );
				// printf( " (no call found)" );
				invalid_call = true;
			}

			if ( ZYAN_SUCCESS( ZydisDecoderDecodeFull( &decoder, instruction_buffer + 6, 4, &instruction, operands ) ) )
			{
				if ( instruction.mnemonic == ZYDIS_MNEMONIC_JMP )
				{
					/* jmp [reg] */
					if ( operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY )
					{
						uintptr_t jmp_address{ }, jmp_address_reference{ };

						switch ( operands[ 0 ].mem.base )
						{
							case ZYDIS_REGISTER_R12:
							{
								jmp_address_reference = context.R12;
								break;
							}
							case ZYDIS_REGISTER_R13:
							{
								jmp_address_reference = context.R13;
								break;
							}
							case ZYDIS_REGISTER_R14:
							{
								jmp_address_reference = context.R14;
								break;
							}
							case ZYDIS_REGISTER_R15:
							{
								jmp_address_reference = context.R15;
								break;
							}
							case ZYDIS_REGISTER_RDI:
							{
								jmp_address_reference = context.Rdi;
								break;
							}
							case ZYDIS_REGISTER_RSI:
							{
								jmp_address_reference = context.Rsi;
								break;
							}
							case ZYDIS_REGISTER_RBX:
							{
								jmp_address_reference = context.Rbx;
								break;
							}
							case ZYDIS_REGISTER_RBP:
							{
								jmp_address_reference = context.Rbp;
								break;
							}
							default:
								break;
						}

						if ( jmp_address_reference && ReadProcessMemory( process, ( LPCVOID ) jmp_address_reference, &jmp_address, sizeof( uintptr_t ), nullptr ) )
						{
							if ( !in_valid_module( jmp_address, GetProcessId( process ) ) )
							{
								raised_flags++;
								sw_logs.emplace_back( " (jmp to unbacked memory region)" );
								unbacked_code = true;
							}
							if ( jmp_address != stack_frame.AddrReturn.Offset )
							{
								raised_flags++;
								sw_logs.emplace_back( " (jmp to unexpected memory region)" );
								address_discrepancy = true;
							}
						}
					}
					/* jmp reg */
					else if ( operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER )
					{
						uintptr_t jmp_address{ };

						switch ( operands[ 0 ].reg.value )
						{
							case ZYDIS_REGISTER_R12:
							{
								jmp_address = context.R12;
								break;
							}
							case ZYDIS_REGISTER_R13:
							{
								jmp_address = context.R13;
								break;
							}
							case ZYDIS_REGISTER_R14:
							{
								jmp_address = context.R14;
								break;
							}
							case ZYDIS_REGISTER_R15:
							{
								jmp_address = context.R15;
								break;
							}
							case ZYDIS_REGISTER_RDI:
							{
								jmp_address = context.Rdi;
								break;
							}
							case ZYDIS_REGISTER_RSI:
							{
								jmp_address = context.Rsi;
								break;
							}
							case ZYDIS_REGISTER_RBX:
							{
								jmp_address = context.Rbx;
								break;
							}
							case ZYDIS_REGISTER_RBP:
							{
								jmp_address = context.Rbp;
								break;
							}
							default:
								break;
						}

						if ( jmp_address && !in_valid_module( jmp_address, GetProcessId( process ) ) )
						{
							raised_flags++;
							sw_logs.emplace_back( " (jmp to unbacked memory region)" );
							unbacked_code = true;
						}
						if ( jmp_address != stack_frame.AddrReturn.Offset )
						{
							raised_flags++;
							sw_logs.emplace_back( " (jmp to unexpected memory region)" );
							address_discrepancy = true;
						}
					}
				}
			}
		}

		DWORD64 image_base{ };
		UNWIND_HISTORY_TABLE history_table{ };
		const auto function_entry = RtlLookupFunctionEntry( frame_return_address, &image_base, &history_table );
		if ( function_entry )
			last_function_address = image_base + function_entry->BeginAddress;
		else
			last_function_address = frame_return_address - displacement;

		sw_logs.emplace_back( tfm::format( "\n" ) );

		frame_count++;
	}

	if ( unbacked_code || invalid_call || address_discrepancy )
	{
		for ( const auto& sw_log : sw_logs )
			printf( sw_log.c_str( ) );

		printf( "\nwarning: possible stack tampering detected\n" );

		if ( unbacked_code )
			printf( " * found code in unbacked memory region\n" );
		if ( invalid_call )
			printf( " * found return address with no previous call\n" );
		if ( address_discrepancy )
			printf( " * found call address discrepancy\n" );

		printf( "\ntotal raised flags: %d\n", raised_flags );
	}
	else if ( logging & LOG_VERBOSE )
	{
		for ( const auto& sw_log : sw_logs )
			printf( sw_log.c_str( ) );
	}

	printf( "-------------------------------------\n" );

	SymCleanup( process );
}

uintptr_t uw::query_unwind_info( const uintptr_t image_base, const uintptr_t* function_address, const log logging, DWORD64* stack_size, operation* uwop, const sig_scan* signature_scan )
{
	const auto abort = [ & ]( const char* msg, ... ) -> int
	{
		if ( logging & LOG_RESULTS )
		{
			printf( "[virtual_unwind] error: ");
			va_list args;
			va_start( args, msg );
			vprintf( msg, args );
			va_end( args );
			printf( "\n" );
		}
		return false;
	};

	if ( !image_base )
		return abort( "invalid image base" );

	if ( function_address && !*function_address )
		return abort( "invalid function address" );

	if ( uwop )
		uwop->offset = 0;

	const auto nt_headers = ( PIMAGE_NT_HEADERS ) ( image_base + PIMAGE_DOS_HEADER( image_base )->e_lfanew );
	if ( !nt_headers || nt_headers->Signature != IMAGE_NT_SIGNATURE )
		return abort( "could not parse ntheader" );

	const auto exception_directory = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ];
	if ( !exception_directory.Size || !exception_directory.VirtualAddress )
		return abort( "could not parse exception directory" );

	/* @https://klezvirus.github.io/RedTeaming/AV_Evasion/StackSpoofing/assets/runtime_exception_table.png */
	auto entry = ( PRUNTIME_FUNCTION ) ( image_base + exception_directory.VirtualAddress );
	const auto end = ( PRUNTIME_FUNCTION ) ( image_base + exception_directory.VirtualAddress + exception_directory.Size );

	uintptr_t out_func_address{ };

	/* @https://doxygen.reactos.org/d8/d2f/unwind_8c_source.html */
	do
	{
		if ( function_address && entry->BeginAddress != ( *function_address - image_base ) )
		{
			entry++;
			continue;
		}

		std::vector<std::string> opcode_logs{ };
		DWORD64 temp_stack_size{ };

		if ( !stack_size )
			stack_size = &temp_stack_size;

		*stack_size = 0;

		ULONG i{ };
		const auto function_unwind = ( PUNWIND_INFO ) ( image_base + entry->UnwindData );
		while ( i < function_unwind->CountOfCodes )
		{
			const auto& unwind_code = function_unwind->UnwindCode[ i ];

			if ( uwop )
			{
				if ( uwop->op_code == unwind_code.UnwindOp && unwind_code.UnwindOp == UWOP_SET_FPREG && uwop->op_register == function_unwind->FrameRegister )
				{
					out_func_address = ( entry->BeginAddress + image_base );
					uwop->offset = *stack_size;
				}
				else if ( uwop->op_code == unwind_code.UnwindOp && uwop->op_register == unwind_code.OpInfo )
				{
					out_func_address = ( entry->BeginAddress + image_base );
					uwop->offset = *stack_size;
				}
			}

			switch ( unwind_code.UnwindOp )
			{
				case UWOP_PUSH_NONVOL:
				{
					if ( logging & LOG_OPCODES )
					{
						char register_name[ 4 ];
						internal::translate_register( unwind_code.OpInfo, register_name );
						opcode_logs.emplace_back( tfm::format( "push %s\n", register_name ) );
					}

					*stack_size += sizeof( DWORD64 );

					i++;
					break;
				}
				case UWOP_ALLOC_LARGE:
				{
					ULONG offset = 0;
					if ( unwind_code.OpInfo )
					{
						offset = *( ULONG* ) ( &function_unwind->UnwindCode[ i + 1 ] );
						*stack_size += offset;

						i += 3;
					}
					else
					{
						offset = ( function_unwind->UnwindCode[ i + 1 ].FrameOffset * 8 );
						*stack_size += offset;

						i += 2;
					}

					if ( logging & LOG_OPCODES )
						opcode_logs.emplace_back( tfm::format( "sub RSP, %lu\n", offset ) );

					break;
				}
				case UWOP_ALLOC_SMALL:
				{
					const ULONG offset = ( ( unwind_code.OpInfo + 1 ) * 8 );
					*stack_size += offset;

					if ( logging & LOG_OPCODES )
						opcode_logs.emplace_back( tfm::format( "sub RSP, %lu\n", offset ) );

					i++;
					break;
				}
				case UWOP_SET_FPREG:
				{
					const auto frame_offset = DWORD64( 0x10 * ( function_unwind->FrameOffset ) );

					if ( logging & LOG_OPCODES )
					{
						char register_name[ 4 ];
						internal::translate_register( function_unwind->FrameRegister, register_name );
						opcode_logs.emplace_back( frame_offset ? tfm::format( "lea %s, [RSP+%llu]\n", register_name, frame_offset ) : tfm::format( "mov %s, RSP\n", register_name ) );
					}

					*stack_size -= frame_offset;

					i++;
					break;
				}
				case UWOP_PUSH_MACHFRAME:
				{
					i++;
					break;
				}
				case UWOP_SAVE_NONVOL:
				{
					i += 2;
					break;
				}
				case UWOP_SAVE_NONVOL_FAR:
				{
					i += 3;
					break;
				}
				default:
				{
					i++;
					break;
				}
			}
		}

		if ( function_unwind->Flags & UNW_FLAG_CHAININFO )
		{

		}

		auto print_unwind = [ & ]( ) -> void
		{
			if ( logging & LOG_VERBOSE )
			{
				SymInitialize( GetCurrentProcess( ), nullptr, TRUE );

				const auto function_address{ ( entry->BeginAddress + image_base ) };
				IMAGEHLP_MODULE64 module_info = { sizeof( IMAGEHLP_MODULE64 ) };
				if ( SymGetModuleInfo64( GetCurrentProcess( ), function_address, &module_info ) )
				{
					BYTE buffer[ sizeof( SYMBOL_INFO ) + MAX_SYM_NAME * sizeof( TCHAR ) ];
					const PSYMBOL_INFO symbol = ( PSYMBOL_INFO ) buffer;
					symbol->SizeOfStruct = sizeof( SYMBOL_INFO );
					symbol->MaxNameLen = MAX_SYM_NAME;

					DWORD64 displacement{ };
					if ( SymFromAddr( GetCurrentProcess( ), ( DWORD64 ) function_address, &displacement, symbol ) )
						printf( "%s!%s ", ( strrchr( module_info.ImageName, '\\' ) + 1 ), symbol->Name );
					else
						printf( "%s+0x%llx ", ( strrchr( module_info.ImageName, '\\' ) + 1 ), ( function_address - module_info.BaseOfImage ) );
				}
				else
				{
					printf( "function not backed by valid module " );
				}

				printf( "@ 0x%p\n", function_address );

				if ( logging & LOG_OPCODES )
				{
					for ( const auto& opcode_log : opcode_logs )
						printf( opcode_log.c_str( ) );
				}

				if ( logging & LOG_RESULTS )
				{
					if ( uwop && out_func_address )
						printf( "uwop offset: %" PRIu64 " bytes\n", uwop->offset );

					printf( "stack size: %" PRIu64 " bytes\n", *stack_size );
				}

				printf( "-------------------------------------\n" );

				SymCleanup( GetCurrentProcess( ) );
			}
		};

		/* address search */
		if ( function_address && !uwop )
		{
			print_unwind( );
			return *function_address;
		}

		/* uwop search */
		if ( uwop && out_func_address )
		{
			print_unwind( );
			return out_func_address;
		}

		/* signature search */
		if ( signature_scan && signature_scan->pattern )
		{
			const auto direct_sig_address = util::sig_scan( signature_scan->pattern, ( entry->BeginAddress + image_base ), ( entry->EndAddress + image_base ) );
			if ( direct_sig_address )
			{
				print_unwind( );
				return signature_scan->return_type == sig_scan::DIRECT_ADDRESS ? direct_sig_address : ( entry->BeginAddress + image_base );
			}
		}

		entry++;

	} while ( entry != end );

	if ( function_address && !uwop )
		return abort( "function with address 0x%p not found", *function_address );

	if ( uwop )
		return abort( "function with uwop not found" );

	if ( signature_scan )
		return abort( "signature not found" );

	return abort( "no search parameters specified" );
}