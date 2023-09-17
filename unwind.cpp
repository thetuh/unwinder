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

uintptr_t uw::virtual_unwind( const uintptr_t image_base, const uintptr_t* function_address, const log logging, const char* function_name, DWORD64* stack_size, operation* uwop, const sig_scan* signature_scan )
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

	constexpr char func_name[] = "function";
	if ( !function_name )
		function_name = func_name;

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

		if ( logging & LOG_VERBOSE )
			printf( "%s @ 0x%p:\n", function_name, ( entry->BeginAddress + image_base ) );

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
						translate_register( unwind_code.OpInfo, register_name );
						printf( "push %s\n", register_name );
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
						printf( "sub RSP, %lu\n", offset );

					break;
				}
				case UWOP_ALLOC_SMALL:
				{
					const ULONG offset = ( ( unwind_code.OpInfo + 1 ) * 8 );
					*stack_size += offset;

					if ( logging & LOG_OPCODES )
						printf( "sub RSP, %lu\n", offset );

					i++;
					break;
				}
				case UWOP_SET_FPREG:
				{
					const auto frame_offset = DWORD64( 0x10 * ( function_unwind->FrameOffset ) );

					if ( logging & LOG_OPCODES )
					{
						char register_name[ 4 ];
						translate_register( function_unwind->FrameRegister, register_name );
						frame_offset ? printf( "lea %s, [RSP+%llu]\n", register_name, frame_offset ) : printf( "mov %s, RSP\n", register_name);
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

		if ( logging & LOG_RESULTS )
		{
			if ( uwop && out_func_address )
				printf( "uwop offset: %" PRIu64 " bytes\n", uwop->offset );

			printf( "stack size: %" PRIu64 " bytes\n", *stack_size );
		}

		if ( logging & LOG_VERBOSE )
			printf( "-------------------------------------\n" );

		/* exlusive address-based search */
		if ( function_address && !uwop )
			return *function_address;

		/* uwop-based search */
		if ( uwop && out_func_address )
			return out_func_address;

		/* signature-based search */
		if ( signature_scan && signature_scan->pattern )
		{
			const auto direct_sig_address = util::sig_scan( signature_scan->pattern, ( entry->BeginAddress + image_base ), ( entry->EndAddress + image_base ) );
			if ( direct_sig_address )
				return signature_scan->return_type == sig_scan::DIRECT_ADDRESS ? direct_sig_address : ( entry->BeginAddress + image_base );
		}

		entry++;

	} while ( entry != end );

	if ( function_address && !uwop )
		return abort( "function '%s' with address 0x%p not found", function_name, *function_address );

	if ( uwop )
		return abort( "function '%s' with uwop not found", function_name );

	if ( signature_scan )
		return abort( "signature not found" );

	return abort( "no search parameters specified" );
}