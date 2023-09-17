
.data

spoof_info STRUCT

	set_fpreg_frame DQ 1
	set_fpreg_frame_size DQ 1
	set_fpreg_frame_random_offset DQ 1

	push_rbp_frame DQ 1
	push_rbp_offset DQ 1
	push_rbp_frame_size DQ 1
	push_rbp_frame_random_offset DQ 1

	jmp_rbx_gadget DQ 1
	jmp_rbx_gadget_ref DQ 1
	jmp_rbx_gadget_frame_size DQ 1

	add_rsp_gadget DQ 1
	add_rsp_gadget_frame_size DQ 1

	target_function DQ 1
	return_address DQ 1

	num_args DQ 1
	arg1 DQ 1
	arg2 DQ 1
	arg3 DQ 1
	arg4 DQ 1
	arg5 DQ 1
	arg6 DQ 1
	arg7 DQ 1
	arg8 DQ 1

spoof_info ENDS

.code

spoof_call proc
; -------------------------------------------------------------
; save non-volatile registers
; -------------------------------------------------------------
	mov [rsp+08h], rbp
	mov [rsp+10h], rbx

; -------------------------------------------------------------
; create stack reference to the jmp rbx gadget
; -------------------------------------------------------------
	mov rbx, [rcx].spoof_info.jmp_rbx_gadget
	mov [rsp+18h], rbx
	mov rbx, rsp
	add rbx, 18h
	mov [rcx].spoof_info.jmp_rbx_gadget_ref, rbx

; -------------------------------------------------------------
; prolog
; -------------------------------------------------------------
	mov rbp, rsp

	lea rax, restore
	push rax
	
	; will be called by jmp_rbx_gadget
	lea rbx, [rsp]

; -------------------------------------------------------------
; first frame (mov rbp, rsp)
; -------------------------------------------------------------
	push [rcx].spoof_info.set_fpreg_frame
	mov rax, [rcx].spoof_info.set_fpreg_frame_random_offset
	add qword ptr [rsp], rax
	
	mov rax, [rcx].spoof_info.return_address
	sub rax, [rcx].spoof_info.set_fpreg_frame_size

	sub rsp, [rcx].spoof_info.push_rbp_frame_size
	mov r10, [rcx].spoof_info.push_rbp_offset
	mov [rsp+r10], rax

; -------------------------------------------------------------
; second frame (push rbp)
; -------------------------------------------------------------
	push [rcx].spoof_info.push_rbp_frame
	mov rax, [rcx].spoof_info.push_rbp_frame_random_offset
	add qword ptr [rsp], rax

; -------------------------------------------------------------
; third frame (jmp rbx)
; -------------------------------------------------------------
	sub rsp, [rcx].spoof_info.jmp_rbx_gadget_frame_size
	push [rcx].spoof_info.jmp_rbx_gadget_ref
	sub rsp, [rcx].spoof_info.spoof_info.add_rsp_gadget_frame_size
	mov r10, [rcx].spoof_info.jmp_rbx_gadget
	mov [rsp+38h], r10

	push [rcx].spoof_info.add_rsp_gadget
	mov rax, [rcx].spoof_info.add_rsp_gadget_frame_size
	mov [rbp+28h], rax

	mov rax, [rcx].spoof_info.target_function
	jmp parameter_handler
	jmp execute
spoof_call endp

restore proc
	mov     rsp, rbp
	mov     rbp, [rsp+08h]
	mov     rbx, [rsp+10h]
	ret
restore endp

parameter_handler proc
	mov		r9, rax
	mov		rax, 8
	mov		r8, [rcx].spoof_info.num_args	
	mul		r8
;	pop		rdx
;	sub		rsp, rax -- Not necessary
;	push	rdx
	xchg	r9, rax
	cmp		[rcx].spoof_info.num_args, 8
	je		handle_eight
	cmp		[rcx].spoof_info.num_args, 7
	je		handle_seven
	cmp		[rcx].spoof_info.num_args, 6
	je		handle_six
	cmp		[rcx].spoof_info.num_args, 5
	je		handle_five
	cmp		[rcx].spoof_info.num_args, 4
	je		handle_four
	cmp		[rcx].spoof_info.num_args, 3
	je		handle_three
	cmp		[rcx].spoof_info.num_args, 2
	je		handle_two
	cmp		[rcx].spoof_info.num_args, 1
	je 		handle_one
	cmp		[rcx].spoof_info.num_args, 0
	je 		handle_none
parameter_handler endp

handle_eight proc
	push	r15
	mov		r15, [rcx].spoof_info.arg8
	mov		[rsp+48h], r15
	pop		r15
	jmp		handle_seven
handle_eight endp
handle_seven proc
	push	r15
	mov		r15, [rcx].spoof_info.arg7
	mov		[rsp+40h], r15
	pop		r15
	jmp		handle_six
handle_seven endp
handle_six proc
	push	r15
	mov		r15, [rcx].spoof_info.arg6
	mov		[rsp+38h], r15
	pop		r15
	jmp		handle_five
handle_six endp
handle_five proc
	push	r15
	mov		r15, [rcx].spoof_info.arg5
	mov		[rsp+30h], r15
	pop		r15
	jmp		handle_four
handle_five endp
handle_four proc
	mov		r9, [rcx].spoof_info.arg4
	jmp		handle_three
handle_four endp
handle_three proc
	mov		r8, [rcx].spoof_info.arg3
	jmp		handle_two
handle_three endp
handle_two proc
	mov		rdx, [rcx].spoof_info.arg2
	jmp		handle_one
handle_two endp
handle_one proc
	mov		rcx, [rcx].spoof_info.arg1
	jmp		handle_none
handle_one endp

handle_none proc
	jmp		execute
handle_none endp

execute proc
	jmp     qword ptr rax
execute endp

end