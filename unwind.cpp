#include "includes.h"

DWORD64 unwind::calculate_stack_size( const uintptr_t image_base, const char* export_name, const log logging )
{
	constexpr auto msg_prefix = "[calculate_stack_size]";
	const auto abort = [ & ]( const char* msg, ... ) -> int
	{
		if ( logging & LOG_ERRORS )
		{
			printf( "%s error: ", msg_prefix );
			va_list args;
			va_start( args, msg );
			vprintf( msg, args );
			va_end( args );
			printf( "\n" );
		}
		return 0;
	};

	if ( !image_base )
		return abort( "invalid image base" );

	const auto export_address = ( uintptr_t ) GetProcAddress( ( HMODULE ) image_base, export_name );
	if ( !export_address )
		return abort( "could not retrieve function export '%s'", export_name);

	return calculate_stack_size( image_base, export_address, logging, export_name );
}

DWORD64 unwind::calculate_stack_size( const uintptr_t image_base, const uintptr_t function_address, const log logging, const char* function_name )
{
	constexpr auto msg_prefix = "[calculate_stack_size]";
	const auto abort = [ & ]( const char* msg, ... ) -> int
	{
		if ( logging & LOG_ERRORS )
		{
			printf( "%s error: ", msg_prefix );
			va_list args;
			va_start( args, msg );
			vprintf( msg, args );
			va_end( args );
			printf( "\n" );
		}
		return 0;
	};

	if ( !image_base )
		return abort( "invalid image base" );

	if ( !function_address )
		return abort( "invalid function address" );

	const auto nt_headers = ( PIMAGE_NT_HEADERS ) ( image_base + PIMAGE_DOS_HEADER( image_base )->e_lfanew );
	if ( !nt_headers || nt_headers->Signature != IMAGE_NT_SIGNATURE )
		return abort( "could not parse ntheader" );

	const auto exception_directory = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ];
	if ( !exception_directory.Size || !exception_directory.VirtualAddress )
		return abort( "could not exception directory" );

	/* @https://klezvirus.github.io/RedTeaming/AV_Evasion/StackSpoofing/assets/runtime_exception_table.png */
	auto entry = ( PRUNTIME_FUNCTION ) ( image_base + exception_directory.VirtualAddress );
	const auto end = ( PRUNTIME_FUNCTION ) ( image_base + exception_directory.VirtualAddress + exception_directory.Size );

	/* @https://doxygen.reactos.org/d8/d2f/unwind_8c_source.html */
	do
	{
		DWORD64 stack_size{ };
		ULONG i{ };

		if ( entry->BeginAddress != ( function_address - image_base ) )
		{
			entry++;
			continue;
		}

		printf( "%s @ 0x%p:\n", function_name, function_address );

		const auto function_unwind = ( PUNWIND_INFO ) ( image_base + entry->UnwindData );
		while ( i < function_unwind->CountOfCodes )
		{
			const auto& unwind_code = function_unwind->UnwindCode[ i ];
			switch ( function_unwind->UnwindCode[ i ].UnwindOp )
			{
				case UWOP_PUSH_NONVOL:
				{
					if ( logging & LOG_OPCODES )
					{
						printf( "push " );
						switch ( unwind_code.OpInfo )
						{
							case R12:
							{
								printf( "R12\n" );
								break;
							}
							case R13:
							{
								printf( "R13\n" );
								break;
							}
							case R14:
							{
								printf( "R14\n" );
								break;
							}
							case R15:
							{
								printf( "R15\n" );
								break;
							}
							case RDI:
							{
								printf( "RDI\n" );
								break;
							}
							case RSI:
							{
								printf( "RSI\n" );
								break;
							}
							case RBX:
							{
								printf( "RBX\n" );
								break;
							}
							case RBP:
							{
								printf( "RBP\n" );
								break;
							}
							case RSP:
							{
								printf( "RSP\n" );
								break;
							}
							default:
							{
								printf( "%d\n", unwind_code.OpInfo );
								break;
							}
						}
					}

					stack_size += sizeof( DWORD64 );
					i++;
					break;
				}
				case UWOP_ALLOC_LARGE:
				{
					ULONG offset = 0;
					if ( unwind_code.OpInfo )
					{
						offset = *( ULONG* ) ( &function_unwind->UnwindCode[ i + 1 ] );
						stack_size += offset;
						i += 3;
					}
					else
					{
						offset = ( function_unwind->UnwindCode[ i + 1 ].FrameOffset * 8 );
						stack_size += offset;
						i += 2;
					}

					printf( "sub RSP, %lu\n", offset );

					break;
				}
				case UWOP_ALLOC_SMALL:
				{
					const ULONG offset = ( ( unwind_code.OpInfo + 1 ) * 8 );
					stack_size += offset;

					if ( logging & LOG_VERBOSE )
						printf( "sub RSP, %lu\n", offset );

					i++;
					break;
				}
				case UWOP_SET_FPREG:
				{
					i++;
					break;
				}
				case UWOP_PUSH_MACHFRAME:
				{
					i++;
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

		printf( "stack size: %" PRIu64 " bytes\n-------------------------------------\n", stack_size );
		return stack_size;

		//entry++;

	} while ( entry != end );

	return abort( "function '%s' not found in RUNTIME_FUNCTION table" );
}
