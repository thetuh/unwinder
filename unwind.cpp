#include "includes.h"

void uw::translate_register( UBYTE op_info, char* register_name )
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

DWORD64 uw::virtual_unwind( const uintptr_t image_base, const uintptr_t function_address, const log logging, const char* function_name )
{
	constexpr auto msg_prefix = "[calculate_stack_size]";
	const auto abort = [ & ]( const char* msg, ... ) -> int
	{
		if ( logging & LOG_RESULTS )
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
		return abort( "could not parse exception directory" );

	/* @https://klezvirus.github.io/RedTeaming/AV_Evasion/StackSpoofing/assets/runtime_exception_table.png */
	auto entry = ( PRUNTIME_FUNCTION ) ( image_base + exception_directory.VirtualAddress );
	const auto end = ( PRUNTIME_FUNCTION ) ( image_base + exception_directory.VirtualAddress + exception_directory.Size );

	/* @https://doxygen.reactos.org/d8/d2f/unwind_8c_source.html */
	do
	{
		DWORD64 stack_size{ };
		DWORD64 return_address_offset{ };
		ULONG i{ };

		if ( entry->BeginAddress != ( function_address - image_base ) )
		{
			entry++;
			continue;
		}

		if ( logging & LOG_VERBOSE )
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
						char register_name[ 4 ];
						translate_register( unwind_code.OpInfo, register_name );
						printf( "push %s\n", register_name );
					}

					return_address_offset += sizeof( DWORD64 );
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
						return_address_offset += offset;
						stack_size += offset;
						i += 3;
					}
					else
					{
						offset = ( function_unwind->UnwindCode[ i + 1 ].FrameOffset * 8 );
						return_address_offset += offset;
						stack_size += offset;
						i += 2;
					}

					if ( logging & LOG_OPCODES )
						printf( "sub RSP, %lu\n", offset );

					break;
				}
				case UWOP_ALLOC_SMALL:
				{
					const ULONG offset = ( ( unwind_code.OpInfo + 1 ) * 8 );
					stack_size += offset;
					return_address_offset += offset;

					if ( logging & LOG_OPCODES )
						printf( "sub RSP, %lu\n", offset );

					i++;
					break;
				}
				case UWOP_SET_FPREG:
				{
					const auto frame_offset = DWORD64( 0x10 * ( function_unwind->FrameOffset ) );
					return_address_offset -= frame_offset;

					if ( logging & LOG_OPCODES )
					{
						char register_name[ 4 ];
						translate_register( function_unwind->FrameRegister, register_name );
						frame_offset ? printf( "lea %s, [RSP+%llu]\n", register_name, frame_offset ) : printf( "mov %s, RSP", register_name);
					}

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

		if ( logging & LOG_RESULTS )
		{
			printf( "return address offset: RSP+%" PRIu64 "\n", return_address_offset );
			printf( "stack size: %" PRIu64 " bytes\n-------------------------------------\n", stack_size );
		}

		return stack_size;

		//entry++;

	} while ( entry != end );

	return abort( "function '%s' not found in RUNTIME_FUNCTION table" );
}
