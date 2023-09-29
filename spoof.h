#pragma once

struct spoof_info
{
	PVOID set_fpreg_frame;
	UINT64 set_fpreg_frame_size;
	UINT64 set_fpreg_frame_random_offset;

	PVOID push_rbp_frame;
	UINT64 push_rbp_offset;
	UINT64 push_rbp_frame_size;
	UINT64 push_rbp_frame_random_offset;

	PVOID jmp_rbx_gadget;
	PVOID jmp_rbx_gadget_ref;
	UINT64 jmp_rbx_gadget_frame_size;

	PVOID add_rsp_gadget;
	UINT64 add_rsp_gadget_frame_size;

	PVOID arbitrary_frame;
	UINT64 arbitrary_frame_size;

	PVOID target_function;
	PVOID return_address;

	UINT64 num_args;
	PVOID arg1;
	PVOID arg2;
	PVOID arg3;
	PVOID arg4;
	PVOID arg5;
	PVOID arg6;
	PVOID arg7;
	PVOID arg8;
};

EXTERN_C PVOID spoof_call( spoof_info* config );
EXTERN_C PVOID experimental_spoof( spoof_info* config );